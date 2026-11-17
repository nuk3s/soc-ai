"""Verdict/action mutations: execute-action, resolve, override."""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass
from typing import Any, Literal
from uuid import uuid4
from weakref import WeakValueDictionary

from fastapi import Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy import select

from soc_ai.api.deps import get_elastic, get_settings_dep
from soc_ai.api.security import identify_caller
from soc_ai.api.webui import _timeline, action_rules
from soc_ai.api.webui._shared import (
    _iso_utc,
    router,
)
from soc_ai.api.webui._timeline import (
    _ACTION_TITLE,
    _action_identity,
    _executed_actions,
)
from soc_ai.campaigns import refresh as campaign_refresh
from soc_ai.campaigns import service as campaign_svc
from soc_ai.config import Settings
from soc_ai.so_client.elastic import ElasticClient
from soc_ai.store import authorized_activity as authorized_svc
from soc_ai.store import chat as chat_svc
from soc_ai.store import escalations as esc_svc
from soc_ai.store import investigations as inv_svc
from soc_ai.store.auth import utcnow
from soc_ai.store.models import Hunt, Investigation, InvestigationEvent
from soc_ai.tools.escalate_to_case import _EVENT_ID_RE, fit_case_description, fit_case_title
from soc_ai.tools.write_exec import FINDING_CASE_TOOL, WRITE_TOOLS, execute_write_tool
from soc_ai.triage_models import drop_case_comments_without_a_case
from soc_ai.webui import alerts_query as aq
from soc_ai.webui import anchor_check, case_links

_LOGGER = logging.getLogger(__name__)

# The status of a refusal of the execute route, by the code of the rule. A
# write against the analyst verdict is a conflict. An anchor the grid did not
# answer for is a grid outage: the press can work later. Every other rule is
# a bad request.
_BLOCK_STATUS = {
    action_rules.CODE_ANALYST: 409,
    action_rules.CODE_AUTHORIZED: 409,
    action_rules.CODE_CAMPAIGN: 409,
    action_rules.CODE_ANCHOR_UNREAD: 503,
}

# Window for the group-scoped ack below. The drawer doesn't know which time
# window the Alerts screen is showing, so use a generous fixed one — wide
# enough to cover any realistic queue view, still bounded by _ACK_CAP.
_GROUP_ACK_RANGE = "7d"
# The same window, in the words the card and the receipt use.
_GROUP_ACK_RANGE_LABEL = "the last 7 days"


# ── Advisory action execution ──────────────────────────────────────────────
# Synth-first investigations recommend write actions in the report rather than
# pausing the agent mid-run, so the analyst executes them on demand from the
# report. These run through the single audited execute_write_tool path,
# restricted to the three write tools, with the alert id defaulted from
# the investigation when the model left it off.


class ExecuteActionResult(BaseModel):
    status: str  # "executed" | "error"
    title: str
    detail: str = ""
    error: str | None = None
    # How many alerts the write reached, when it wrote to alerts. The card
    # reports it after the write (dogfood 2026-10-06, first hour S2).
    count: int | None = None


def _case_id_from_result(result: Any) -> str:
    """The SO case id from an ``escalate_to_case`` tool result (id/caseId/case_id)."""
    if not isinstance(result, dict):
        return ""
    return str(result.get("id") or result.get("caseId") or result.get("case_id") or "")


def _observed_case_id(events: list[Any]) -> str | None:
    """The SO case id of THIS investigation's escalate, if any.

    Scans persisted successful ``action_executed`` events for an
    ``escalate_to_case`` execution and returns the case id the system observed:
    from SO's response when the press opened the case, or from the ledger or
    the case links when the alert of the run was already on one (persisted as
    ``case_id`` in both cases). This is the ONLY case id an
    ``add_case_comment`` action may target: ``RecommendedAction.tool_args`` is
    fully model-authored and attacker-influenceable, so the model's free-form
    ``case_id`` is never trusted as a write target (F07). Returns the most
    recent one, or ``None`` when this investigation opened no case.
    """
    found: str | None = None
    for e in events:
        if e.kind != "action_executed":
            continue
        p = e.payload or {}
        if not p.get("success") or p.get("tool_name") != "escalate_to_case":
            continue
        cid = p.get("case_id")
        if isinstance(cid, str) and cid:
            found = cid
    return found


def _escalate_outcome(result: Any) -> tuple[bool, str]:
    """``(linked, sentence)`` for an ``escalate_to_case`` result.

    An escalate is three writes and only the first is guaranteed. Creating the
    case always succeeds once Security Onion answers, so reading the outcome off
    that alone reported success for a press that put the alert on nothing: on
    the range, an alert that was no longer on the grid produced a case, an
    accepted attach that attached nothing, and "Case created: ...".

    ``linked`` is the only thing that decides whether an escalate happened, and
    it is what the caller keys the count and the ledger claim on. The three
    outcomes get three different sentences:

    * attached and stamped: the ordinary escalate.
    * attached, not stamped: the alert IS case work, but Security Onion's own
      alert list still shows it untriaged, so somebody will meet it there.
    * not attached: no escalate happened, and an empty case is now sitting in
      the queue under a title that reads like an incident. Name it, because
      only the operator can close or reuse it.
    """
    if not isinstance(result, dict):
        return False, "Security Onion returned no answer to the escalate."
    case_id = _case_id_from_result(result)
    named = f"case {case_id}" if case_id else "the case"
    if not result.get("alert_linked"):
        reason = (
            str(result.get("link_error") or "").strip().rstrip(".")
            or f"{named} exists and the alert is not attached to it"
        )
        return False, (
            f"{reason[0].upper()}{reason[1:]}. soc-ai recorded no escalation. "
            f"Close or reuse {named}."
        )
    created = (
        f"soc-ai created case {case_id}." if case_id else "soc-ai created a Security Onion case."
    )
    if not result.get("marked_escalated"):
        return True, (
            f"{created} The alert is attached to it. Security Onion did not mark the "
            "alert escalated. The alert still reads as untriaged in the alert list."
        )
    return True, f"{created} The alert is attached to it and marked escalated."


def _action_detail(tool_name: str, result: Any) -> str:
    """One-line, analyst-facing confirmation of what the write tool did."""
    if not isinstance(result, dict):
        return ""
    if tool_name == "ack_alert":
        return "Alert acknowledged in Security Onion."
    if tool_name == "escalate_to_case":
        return _escalate_outcome(result)[1]
    if tool_name == "add_case_comment":
        case_id = result.get("case_id") or ""
        return f"Comment added to case {case_id}." if case_id else "Comment added to case."
    return ""


@dataclass(frozen=True)
class _AckPlan:
    """What a group ack will write, worked out before the write.

    The card used to say "Acknowledge alert" and the server acknowledged every
    unacknowledged alert of the rule from the last 7 days, a true positive
    among them (dogfood 2026-10-06, first hour S2). The plan is what the card
    states before the click and what the write then does, so the two agree.
    """

    ids: list[str]
    # Distinct hosts among the alerts the plan writes.
    hosts: int
    # Alerts the plan leaves alone because a person has to look at them.
    held: int


# Verdicts a group ack does not close. A true positive needs a case, and a
# needs more info verdict waits on a person.
_HELD_VERDICTS = frozenset({"true_positive", "needs_more_info"})


def _event_attr(ev: aq.AlertEvent, name: str) -> str | None:
    """One address field of an alert, read defensively: a test double or an
    older event shape may not carry it."""
    value = getattr(ev, name, None)
    return value if isinstance(value, str) and value else None


def _event_host(ev: aq.AlertEvent) -> str | None:
    """The host one alert concerns: its source address, else its machine."""
    return (
        _event_attr(ev, "src_ip") or _event_attr(ev, "host_ip") or _event_attr(ev, "subject_host")
    )


async def _held_alert_ids(
    request: Request, settings: Settings, rule_name: str, events: list[aq.AlertEvent]
) -> set[str]:
    """The alerts whose own verdict is one a group ack must not close.

    The verdict of an alert is the one the Alerts grid shows on its event row:
    the run of that exact alert, else the run of the same rule and the same
    pair of addresses. A rule-wide standing verdict is not one of these. It is
    the verdict the ack acts on.
    """
    async with request.app.state.db_sessionmaker() as db:
        direct = await inv_svc.latest_for_alerts(db, [ev.es_id for ev in events])
        keys = {
            ev.es_id: inv_svc.pair_key(
                rule_name,
                _event_attr(ev, "src_ip"),
                _event_attr(ev, "dst_ip"),
                _event_attr(ev, "subject_host"),
            )
            for ev in events
        }
        pairs = await inv_svc.latest_for_pairs(
            db, list(set(keys.values())), window_days=settings.webui_inherit_window_days
        )
    held: set[str] = set()
    for ev in events:
        run = direct.get(ev.es_id)
        if run is None or run.status != "complete":
            run = pairs.get(keys[ev.es_id])
        if run is not None and (run.verdict or "") in _HELD_VERDICTS:
            held.add(ev.es_id)
    return held


async def _group_ack_plan(
    request: Request,
    *,
    rule_name: str,
    settings: Settings,
    elastic: ElasticClient,
    own_alert_id: str | None,
) -> _AckPlan | None:
    """Group-scoped ack: the unacked alerts of *rule_name* the ack will write.

    The recommendation card says "Acknowledge alert", but the analyst's intent
    is "this detection is handled" — a single-event ack left the rest of the
    group sitting in the queue after a successful "Executed ✓" (dogfood
    2026-07-15). Same contract as the settled bar / POST /alerts/ack-group.

    Two rules from dogfood 2026-10-06: an alert with a true positive or a needs
    more info verdict of its own is left alone, and the alert of this run is in
    the plan even when it sits outside the window, because the ack the analyst
    asked for must reach it.

    Returns ``None`` — so the caller falls back to the single-alert ack — both
    when the group fetch FAILED and when it came back EMPTY: an empty result is
    ambiguous (an already-clear Suricata group, OR a wrong-field miss on a
    non-Suricata detection, since ``kind`` is hardcoded ``suricata`` and a Zeek
    notice's name lives in ``notice.note``, not ``rule.name``). The single-alert
    path is dataset-agnostic and idempotent, so it is correct for both (F28).
    """
    from soc_ai.api.webui.routes_alert_actions import _ACK_CAP  # noqa: PLC0415

    try:
        events = await aq.fetch_group_events(
            elastic,
            settings,
            rule_name=rule_name,
            kind="suricata",
            time_range=_GROUP_ACK_RANGE,
            size=_ACK_CAP,
            time_zone=settings.so_timezone,
            hide_acked=True,
        )
    except Exception:
        _LOGGER.warning(
            "group ack: event fetch failed for rule %r — falling back to single-alert ack",
            rule_name,
            exc_info=True,
        )
        return None
    if not events:
        # Ambiguous empty result — do NOT claim group success with acked=0 (that
        # falsely marks a non-Suricata alert handled while it stays unacked in SO,
        # F28). Fall back to the single-alert ack keyed on this investigation's own
        # alert_es_id, which is dataset-agnostic and idempotent.
        return None
    try:
        held = await _held_alert_ids(request, settings, rule_name, events)
    except Exception:
        # The store did not answer. Hold nothing back and say nothing about
        # verdicts: the plan still names the count the analyst confirms.
        _LOGGER.warning("group ack: verdict lookup failed for rule %r", rule_name, exc_info=True)
        held = set()
    keep = [ev for ev in events if ev.es_id not in held]
    ids = [ev.es_id for ev in keep]
    if (
        own_alert_id
        and own_alert_id not in {ev.es_id for ev in events}
        and not await _timeline._alert_currently_acked(elastic, settings, own_alert_id)
    ):
        ids.append(own_alert_id)
    hosts = {h for h in (_event_host(ev) for ev in keep) if h}
    return _AckPlan(ids=ids, hosts=len(hosts), held=len(held))


def _alerts(n: int) -> str:
    return f"{n} alert{'s' if n != 1 else ''}"


def _ack_scope_sentence(plan: _AckPlan) -> str:
    """What the group ack will do, said before the click."""
    if not plan.ids:
        head = f"soc-ai has no alert of this rule to acknowledge from {_GROUP_ACK_RANGE_LABEL}."
    else:
        hosts = f", on {plan.hosts} host{'s' if plan.hosts != 1 else ''}" if plan.hosts else ""
        head = (
            f"Acknowledge {_alerts(len(plan.ids))} of this rule from "
            f"{_GROUP_ACK_RANGE_LABEL}{hosts}."
        )
    if plan.held:
        head += (
            f" soc-ai leaves {_alerts(plan.held)} with a true positive or needs more "
            "info verdict open."
        )
    return head


def _ack_done_sentence(plan: _AckPlan, acked: int, failed: int) -> str:
    """What the group ack did, said after the write."""
    if failed:
        text = (
            f"Acknowledged {acked} of {_alerts(acked + failed)} of this rule from "
            f"{_GROUP_ACK_RANGE_LABEL}. {failed} failed."
        )
    else:
        text = f"Acknowledged {_alerts(acked)} of this rule from {_GROUP_ACK_RANGE_LABEL}."
    if plan.held:
        text += (
            f" soc-ai left {_alerts(plan.held)} with a true positive or needs more "
            "info verdict open."
        )
    return text


async def _reserve_escalate(
    request: Request,
    elastic: ElasticClient,
    settings: Settings,
    alert_id: str,
    *,
    user: str,
    inv_real_id: str,
    sequence: int,
    receipt: dict[str, Any],
) -> ExecuteActionResult | None:
    """Reserve ``alert_id`` in the escalation ledger BEFORE a case is opened.

    Returns ``None`` when the claim is ours and the caller may write, or the
    answer to give the analyst when it is not.

    This is the half of the duplicate-case guard the single-alert path did not
    have. Its own idempotency is the persisted ``action_executed`` marker, which
    is keyed to one investigation and one action, and the per-``(investigation,
    action)`` lock above, which is process-local. Neither can see a group
    escalate over the same alert running in the same instant, and the group path
    could not see this one either, because nothing reserved the alert until
    after the case was already open. Both presses passed their own check and
    Security Onion ended with two cases pointing at one alert — the same outcome
    the ledger was introduced to stop, reached through the door it did not
    cover.

    :func:`~soc_ai.api.webui.routes_alert_actions._reserve` is reused rather
    than reimplemented for one alert, so both paths answer "is this already on a
    case" from the same three sources in the same order (ledger, then Security
    Onion's case links, then a claim somebody else holds), and a stale claim the
    grid can disprove is released and retaken here exactly as it is there. A
    second reservation policy would be a second set of answers.
    """
    from soc_ai.api.webui.routes_alert_actions import _reserve  # noqa: PLC0415 — circular

    title = str(receipt.get("title") or "")
    reserved = await _reserve(request, elastic, settings, [alert_id], caller=user)
    if alert_id in reserved.claimed:
        return None
    if reserved.unresolved:
        # An earlier escalate claimed this alert and never came back with a case
        # id, and the grid could not be asked whether one exists. Opening a case
        # now might duplicate one; refusing leaves the alert where it is. Only
        # the second of those is reversible. Answered as an error rather than an
        # execution, so the card stays pressable once the grid is readable.
        return ExecuteActionResult(
            status="error",
            title=title,
            error=(
                "An earlier escalate of this alert is not settled. soc-ai could not read "
                "the Security Onion case index. soc-ai opened no case. Try again once "
                "the grid is readable."
            ),
        )
    # A case already exists. Same shape as the already-acknowledged arm in the
    # caller: ok-with-note, and persist the marker so the card reads applied
    # from now on rather than re-offering a duplicate.
    #
    # The marker names the case when the ledger or the case links name it. A
    # comment beside this escalate binds to the case of the run, and a marker
    # with no case left that comment off for good, with the advice "Escalate
    # the alert first" (review of the lane, defect 8). The id is read by the
    # server for the alert of this run. It is never the model's.
    case_id: str | None = None
    try:
        case_ids, _complete = await case_links.cases_of_alert(
            request.app.state.db_sessionmaker, elastic, settings, alert_id
        )
        case_id = case_ids[0] if case_ids else None
    except Exception:
        _LOGGER.warning("case lookup failed for an alert already on a case", exc_info=True)
    marker: dict[str, Any] = {**receipt, "success": True, "by": user}
    named = "a Security Onion case"
    if case_id:
        marker["case_id"] = case_id
        named = f"Security Onion case {case_id}"
    detail = f"This alert is already on {named}. soc-ai opened no second case."
    await _persist_action_executed(request, inv_real_id, sequence, {**marker, "detail": detail})
    return ExecuteActionResult(status="executed", title=title, detail=detail)


async def _record_escalation(
    request: Request,
    *,
    alert_id: Any,
    case_id: str,
    linked: bool,
) -> None:
    """Resolve this alert's ledger claim with the case that was opened for it.

    The claim itself was taken by :func:`_reserve_escalate` before the write, so
    there is a row here already and this only writes the answer onto it.

    A case id goes on the row only when the alert is genuinely attached to that
    case. Writing one for a case that attached nothing is the poisoning half of
    the range defect: the ledger would then refuse the case actually needed, on
    the strength of a link that does not exist. An unattached escalate leaves
    the bare claim standing, which reads as "soc-ai tried, outcome unknown", and
    the next press of either escalate settles it against the grid.

    Best-effort: the case exists either way, and a store failure must not change
    what the operator is told about the write.
    """
    if not isinstance(alert_id, str) or not alert_id or not linked or not case_id:
        return
    try:
        async with request.app.state.db_sessionmaker() as db:
            await esc_svc.record_case(db, alert_id, case_id)
    except Exception:
        _LOGGER.warning("escalation ledger write failed", exc_info=True)


async def _persist_action_executed(
    request: Request,
    inv_real_id: str,
    sequence: int,
    payload: dict[str, Any],
) -> None:
    """Durably record an advisory-action execution as an investigation event.

    FR-030: without this a reload re-offered an already-executed escalate
    (duplicate SO cases). ``_build_actions`` reads the event back to mark the
    card applied. Best-effort: the write already happened in SO, so a failed
    bookkeeping insert must not turn the response into an error.
    """
    # Every receipt names its time (dogfood 2026-10-06, S3). The actor is the
    # caller's ``by``, which every call site sets.
    stamped = {**payload, "at": payload.get("at") or _now_iso()}
    try:
        async with request.app.state.db_sessionmaker() as db:
            await inv_svc.append_events(
                db,
                inv_real_id,
                [{"sequence": sequence, "kind": "action_executed", "payload": stamped}],
            )
    except Exception:
        _LOGGER.warning(
            "failed to persist action_executed event for %s (action still executed)",
            inv_real_id,
            exc_info=True,
        )


def _now_iso() -> str:
    """Now, as the ISO UTC string the console localizes."""
    return _iso_utc(utcnow())


# The title of a case when the run names no rule. The override path and the
# execute route bind the same words.
_DEFAULT_CASE_TITLE = "soc-ai investigation"


def _text(value: Any) -> str:
    """A stored value as text: the stripped string, or empty for any other type."""
    return value.strip() if isinstance(value, str) else ""


def _bind_case_text(
    tool_args: dict[str, Any],
    *,
    inv_id: str,
    rule_name: str | None,
    headline: str | None,
    rationale: Any,
) -> None:
    """Give an escalate the title and the description it needs.

    ``escalate_to_case`` refuses a call with no title or no description, and
    the model does not always send them. Five true positive runs on production
    held ``"tool_args": {}`` (review 2026-11-13), so Execute failed on the one
    action a true positive offers. The same holds for a value that is not
    text: a ``null`` title reached ``.strip()`` inside the tool.

    A field with text is kept. An empty field is bound from the run, the way
    :func:`_override_actions` binds it: the title is the rule name, and the
    description is the headline of the run, else the reason of this action.
    Every source is a stored field of this investigation. No id is read from
    ``tool_args``, so the binding gives the model no new way to choose what
    the write reaches (F07).
    """
    title = _text(tool_args.get("case_title")) or _text(rule_name) or _DEFAULT_CASE_TITLE
    description = (
        _text(tool_args.get("case_description"))
        or _text(headline)
        or _text(rationale)
        or f"soc-ai investigation {inv_id} recommends this case."
    )
    # Security Onion refuses a title over 100 bytes. The cut is made here too,
    # for a bound title and for the title of the model, so the audit record
    # holds the text that is sent.
    tool_args["case_title"] = fit_case_title(title)
    tool_args["case_description"] = fit_case_description(description)


# ── The case of a promoted finding ─────────────────────────────────────────
# A finding is no alert, and Security Onion creates a case from a title and a
# description alone. "Escalate to case" on a finding run opens a case from the
# stored finding. Every part of the case is a stored field of the hunt or of
# the run. ``tool_args`` is never read: the model's alert id is the anchor
# document, which is cited telemetry, and a model-authored list of alerts to
# attach would be a write target the analyst did not see (F07).

# The description lists at most this many cited documents.
_CASE_DOCUMENTS_MAX = 50
_DEFAULT_FINDING_TITLE = "Hunt finding"


@dataclass(frozen=True)
class _FindingCase:
    """What the escalate of a promoted finding opens."""

    title: str
    description: str
    # The documents the finding cites. The alerts among them can go on the case.
    document_ids: list[str]
    # The hosts the finding names, lowercased. An alert goes on the case only
    # when it is on one of them.
    hosts: frozenset[str]
    # What the one-case guard keys on: the hunt and the finding. Not the run
    # and not the action, so an override, a second action and a later run all
    # meet the same record. A row that names no hunt finding keys on itself.
    identity: str
    hunt_id: str | None
    ordinal: int | None


async def _stored_finding(db: Any, inv: Investigation) -> dict[str, Any] | None:
    """The finding this run was promoted from, or None when the hunt is gone.

    The link carries no foreign key, so it can dangle, and a stored report is
    not schema-checked.
    """
    if not inv.hunt_id or inv.finding_ordinal is None:
        return None
    hunt = await db.get(Hunt, inv.hunt_id)
    report = hunt.report if hunt is not None and isinstance(hunt.report, dict) else {}
    findings = report.get("findings")
    ordinal = int(inv.finding_ordinal)
    if not isinstance(findings, list) or not 0 <= ordinal < len(findings):
        return None
    finding = findings[ordinal]
    return finding if isinstance(finding, dict) else None


async def _finding_case(db: Any, inv: Investigation) -> _FindingCase:
    """The case of the finding run ``inv``, built from stored fields only.

    The title is the title of the finding. The description is the headline of
    the run, then the hosts and the documents the finding cites, then the run
    that judged it. The detail text of the finding stays out: the headline is
    the verdict of the investigation, and the detail is the earlier claim of
    the hunt.

    With the hunt gone, the run still names its title and the documents it
    read (``subject_json``), and the case is built from those.
    """
    from soc_ai.hunting.findings import (  # noqa: PLC0415 - lazy
        DOCUMENT_ID_RE,
        finding_document_ids,
    )

    finding = await _stored_finding(db, inv)
    ordinal = int(inv.finding_ordinal) if inv.hunt_id and inv.finding_ordinal is not None else None
    hosts: list[str] = []
    if finding is not None:
        title = _text(finding.get("title"))
        raw_hosts = finding.get("hosts")
        hosts = [
            str(h).strip()
            for h in (raw_hosts if isinstance(raw_hosts, list) else [])
            if isinstance(h, (str, int)) and not isinstance(h, bool) and str(h).strip()
        ]
        documents = finding_document_ids(finding)
    else:
        title = ""
        subject = inv.subject_json if isinstance(inv.subject_json, dict) else {}
        stored = subject.get("document_ids")
        documents = list(
            dict.fromkeys(
                d
                for d in (stored if isinstance(stored, list) else [])
                if isinstance(d, str) and DOCUMENT_ID_RE.match(d)
            )
        )
    lines = [
        _text(inv.rationale) or f"soc-ai investigation {inv.id} recommends this case.",
        "",
    ]
    if hosts:
        lines.append(f"Hosts: {', '.join(dict.fromkeys(hosts))}")
    if documents:
        lines.append(f"Cited documents: {', '.join(documents[:_CASE_DOCUMENTS_MAX])}")
        if len(documents) > _CASE_DOCUMENTS_MAX:
            lines.append(
                f"The list holds {_CASE_DOCUMENTS_MAX} of {len(documents)} cited documents."
            )
    lines.append(f"Source: soc-ai investigation {inv.id} of a hunt finding.")
    return _FindingCase(
        title=fit_case_title(title or _text(inv.rule_name) or _DEFAULT_FINDING_TITLE),
        description=fit_case_description("\n".join(lines)),
        document_ids=documents,
        hosts=frozenset(h.lower() for h in hosts),
        identity=f"hunt:{inv.hunt_id}:{ordinal}" if ordinal is not None else f"run:{inv.id}",
        hunt_id=inv.hunt_id if ordinal is not None else None,
        ordinal=ordinal,
    )


# The most alerts one finding case attaches: the cap of the group escalate
# (routes_alert_actions._ESCALATE_CAP). Each attach also acknowledges the
# alert in Security Onion, so the number is a blast radius, and the hunt model
# chose the list.
_FINDING_ATTACH_CAP = 25
# The fields of a cited alert that the attach plan reads.
_PLAN_FIELDS = [
    "event.acknowledged",
    "event.escalated",
    "source.ip",
    "destination.ip",
    "host.name",
    "host.ip",
]


@dataclass(frozen=True)
class _FindingState:
    """What the receipts of one finding say: its case, or a press with no result."""

    case_id: str | None
    # The intent of a press that recorded no result. A case can exist.
    open_intent: dict[str, Any] | None


async def _finding_state(request: Request, act: _LoadedAction, case: _FindingCase) -> _FindingState:
    """Read the one-case record of the finding, across runs and actions.

    The record is the ``action_executed`` receipts that carry ``finding_case``,
    on every run of the hunt finding and on this run. The first version read
    the other runs only and matched the receipt to one action, so one finding
    got a second case three ways: an override gave the action a new identity,
    a report held two escalate actions, and a receipt write failed after the
    case existed (review of the lane, defect 2).

    A press writes an intent before it calls Security Onion and a result
    after. An intent with no result is a press whose outcome soc-ai does not
    know: the case can exist.
    """
    async with request.app.state.db_sessionmaker() as db:
        return await _finding_receipt_state(db, act.inv_real_id, case.hunt_id, case.ordinal)


async def _finding_receipt_state(
    db: Any, run_id: str, hunt_id: str | None, ordinal: int | None
) -> _FindingState:
    """The one-case record of the finding of run ``run_id``, read on ``db``.

    ``_finding_state`` reads it for a press and for the confirm. The list of
    waiting actions reads it for a row (``finding_case_blocked``).
    """
    run_ids = {run_id}
    if hunt_id is not None and ordinal is not None:
        run_ids.update(
            (
                await db.scalars(
                    select(Investigation.id).where(
                        Investigation.hunt_id == hunt_id,
                        Investigation.finding_ordinal == ordinal,
                    )
                )
            ).all()
        )
    receipts = (
        await db.scalars(
            select(InvestigationEvent)
            .where(
                InvestigationEvent.investigation_id.in_(sorted(run_ids)),
                InvestigationEvent.kind == "action_executed",
            )
            .order_by(InvestigationEvent.id)
        )
    ).all()
    payloads = [e.payload or {} for e in receipts if (e.payload or {}).get("finding_case")]
    case_id: str | None = None
    settled: set[str] = set()
    for payload in payloads:
        if payload.get("phase") != "intent" and isinstance(payload.get("intent_id"), str):
            settled.add(payload["intent_id"])
        found = payload.get("case_id")
        if payload.get("success") and isinstance(found, str) and found:
            case_id = found
    open_intent = next(
        (
            payload
            for payload in reversed(payloads)
            if payload.get("phase") == "intent" and payload.get("intent_id") not in settled
        ),
        None,
    )
    return _FindingState(case_id=case_id, open_intent=open_intent)


async def finding_case_blocked(db: Any, run: Any) -> bool:
    """True when the escalate of the finding run ``run`` waits on "Try again".

    An earlier press recorded an intent and no result, and the finding is on
    no case. The scope route then answers ``retry`` and the card offers "Try
    again" and no Escalate. The row of the pending list reads the same record,
    so it offers no Escalate that only returns the blocked sentence. The keys
    are the ones ``_finding_case`` builds.
    """
    ordinal = int(run.finding_ordinal) if run.hunt_id and run.finding_ordinal is not None else None
    state = await _finding_receipt_state(
        db, run.id, run.hunt_id if ordinal is not None else None, ordinal
    )
    return state.case_id is None and state.open_intent is not None


def _already_on_case_sentence(case_id: str) -> str:
    return f"This finding is already on Security Onion case {case_id}. soc-ai opens no second case."


def _open_intent_sentence(case: _FindingCase) -> str:
    """A press started a case and recorded no result. Plain, with where to look."""
    return (
        "An earlier press started a Security Onion case for this finding, and soc-ai has "
        "no record of the result. A case can exist. soc-ai opens no case. Look in the "
        f'Cases page of Security Onion for the title "{case.title}".'
    )


@dataclass(frozen=True)
class _AttachPlan:
    """The cited alerts a finding case attaches, and the ones it leaves out."""

    attach: list[str]
    # Security Onion already holds a decision on the alert: acknowledged or escalated.
    decided: int = 0
    # The alert names none of the hosts of the finding.
    off_host: int = 0
    # soc-ai's ledger already has the alert on a case.
    on_case: int = 0
    # Past the cap.
    over_cap: int = 0

    @property
    def skipped(self) -> int:
        return self.decided + self.off_host + self.on_case + self.over_cap


def _alert_hosts(source: dict[str, Any]) -> set[str]:
    """Every host an alert document names: its endpoints and its machine."""
    out: set[str] = set()
    for path in ("source.ip", "destination.ip", "host.name", "host.ip"):
        value = aq._dig(source, path)
        for item in value if isinstance(value, list) else [value]:
            if isinstance(item, str) and item.strip():
                out.add(item.strip().lower())
    return out


async def _finding_attach_plan(request: Request, case: _FindingCase) -> _AttachPlan | None:
    """Which cited alerts the case of a finding attaches. None: the grid did not answer.

    The hunt model chose the cited documents from everything the hunt read,
    and an attach also acknowledges the alert in Security Onion. So the plan
    is narrow, and the card states it before the press:

    * Only a document the alert feed holds. A Zeek record is cited evidence,
      and it is named in the description.
    * Not an alert that already carries a decision in Security Onion
      (acknowledged or escalated), and not one soc-ai's ledger has on a case.
    * Only an alert on a host the finding names.
    * At most :data:`_FINDING_ATTACH_CAP`, in the order the finding cites them.
    """
    state = request.app.state
    settings = state.settings
    ids = [d for d in case.document_ids if _EVENT_ID_RE.match(d)]
    if not ids:
        return _AttachPlan(attach=[])
    try:
        async with asyncio.timeout(settings.webui_grid_timeout_s):
            result = await state.elastic.search(
                settings.events_index_pattern,
                aq.feed_ids_query(settings, ids),
                size=len(ids),
                source=_PLAN_FIELDS,
                # A shard that failed can hold the alert, and its decision.
                require_complete=True,
            )
    except Exception:
        _LOGGER.warning("finding case: the grid did not answer for the cited alerts", exc_info=True)
        return None
    sources = {str(hit.get("_id")): hit.get("_source") or {} for hit in result.hits}
    alerts = [doc_id for doc_id in ids if doc_id in sources]
    async with state.db_sessionmaker() as db:
        ledger = await esc_svc.cases_for_alerts(db, alerts)
    attach: list[str] = []
    decided = off_host = on_case = over_cap = 0
    for alert_id in alerts:
        source = sources[alert_id]
        if aq._source_acknowledged(source) or aq._source_escalated(source):
            decided += 1
        elif ledger.get(alert_id):
            on_case += 1
        elif not (_alert_hosts(source) & case.hosts):
            off_host += 1
        elif len(attach) >= _FINDING_ATTACH_CAP:
            over_cap += 1
        else:
            attach.append(alert_id)
    return _AttachPlan(
        attach=attach, decided=decided, off_host=off_host, on_case=on_case, over_cap=over_cap
    )


def _cited_alerts(n: int) -> str:
    """ "1 alert that the finding cites" / "2 alerts that the finding cites"."""
    return f"{_alerts(n)} that the finding cites"


def _finding_scope_sentence(plan: _AttachPlan) -> str:
    """What the escalate of a finding will do, said before the press."""
    parts = [_FINDING_CASE_SENTENCE]
    n = len(plan.attach)
    if n:
        parts.append(
            f"soc-ai attaches {_cited_alerts(n)}. Security Onion marks each attached "
            "alert escalated and acknowledged."
        )
    else:
        parts.append("soc-ai attaches no alert.")
    if plan.skipped:
        parts.append(f"soc-ai skips {_cited_alerts(plan.skipped)}.")
        reasons = (
            (plan.decided, "already has a decision", "already have a decision"),
            (plan.on_case, "is already on a case", "are already on a case"),
            (plan.off_host, "is not on a host of the finding", "are not on a host of the finding"),
            (plan.over_cap, "is over the limit", "are over the limit"),
        )
        limit = f" of {_FINDING_ATTACH_CAP}"
        for count, one, many in reasons:
            if count:
                tail = limit if "limit" in one else ""
                parts.append(f"{_alerts(count)} {one if count == 1 else many}{tail}.")
    return " ".join(parts)


def _finding_case_sentence(
    case_id: str, *, cited: int, attached: int, skipped: int, failed: int
) -> str:
    """What the escalate of a finding did, said after the write."""
    parts = [f"soc-ai created case {case_id} from the finding."]
    if cited == 0:
        parts.append("The finding cites no Security Onion alert, so the case holds no alert.")
    elif attached:
        parts.append(
            f"{_cited_alerts(attached)} {'is' if attached == 1 else 'are'} attached to it."
        )
    else:
        parts.append("soc-ai attached no alert.")
    if skipped:
        parts.append(f"soc-ai skipped {_cited_alerts(skipped)}.")
    if failed:
        parts.append(f"Security Onion did not attach {_cited_alerts(failed)}.")
    return " ".join(parts)


# One lock for each finding, across its runs and its actions. The per-action
# lock of the execute route cannot see a press on another action of the run.
_FINDING_LOCKS: WeakValueDictionary[str, asyncio.Lock] = WeakValueDictionary()


def _finding_lock(identity: str) -> asyncio.Lock:
    lock = _FINDING_LOCKS.get(identity)
    if lock is None:
        lock = asyncio.Lock()
        _FINDING_LOCKS[identity] = lock
    return lock


async def _record_intent(
    request: Request, inv_real_id: str, sequence: int, payload: dict[str, Any]
) -> bool:
    """Record that a press is about to open a case. False when the store refused.

    Not best-effort, unlike a receipt: the intent is what stops a second case
    when the result is lost, so a press with no intent on record must not
    reach Security Onion.
    """
    try:
        async with request.app.state.db_sessionmaker() as db:
            await inv_svc.append_events(
                db,
                inv_real_id,
                [{"sequence": sequence, "kind": "action_executed", "payload": payload}],
            )
    except Exception:
        _LOGGER.warning("finding case: the intent of the press was not stored", exc_info=True)
        return False
    return True


async def _open_finding_case(
    request: Request,
    act: _LoadedAction,
    *,
    inv_id: str,
    index: int,
    retry: bool = False,
    settings: Settings,
    elastic: ElasticClient,
) -> ExecuteActionResult:
    """Open one Security Onion case from the finding of a promoted run.

    MUST run under ``_action_lock(inv_id, index)``, after the action rule and
    after the check of this action's own receipt. It takes the lock of the
    finding itself for the whole press.

    One finding gets one case. The guard reads the record of the finding
    (:func:`_finding_state`), and the press writes to that record twice: an
    intent before the call to Security Onion and a result after. A press that
    finds a case opens none. A press that finds an intent with no result
    opens none either, and says that a case can exist and where to look: the
    result of that earlier press is unknown, and a second case is the one
    outcome nobody can take back.

    That state has one way out, ``retry``: the analyst looked at the Cases
    page, found no case with the title, and pressed "Try again". The press
    writes an audit record, settles the open intent as cleared and runs the
    open once more. Without it the finding stayed blocked for good after one
    5xx from Security Onion. A finding with a recorded case is not in that
    state, and ``retry`` changes nothing for it.

    The alerts the case attaches are the plan the card stated
    (:func:`_finding_attach_plan`). Each is reserved in the escalation ledger
    first, so a group escalate of the same alert opens no second case.
    """
    case = act.finding_case
    if case is None:  # the action rule passed, so the run is a promoted finding
        raise HTTPException(
            status_code=400, detail={"reason": "not_executable", "tool": act.tool_name}
        )
    async with _finding_lock(case.identity):
        return await _open_finding_case_locked(
            request,
            act,
            case,
            inv_id=inv_id,
            index=index,
            retry=retry,
            settings=settings,
            elastic=elastic,
        )


async def _open_finding_case_locked(
    request: Request,
    act: _LoadedAction,
    case: _FindingCase,
    *,
    inv_id: str,
    index: int,
    retry: bool,
    settings: Settings,
    elastic: ElasticClient,
) -> ExecuteActionResult:
    from soc_ai.api.webui.routes_alert_actions import _reserve  # noqa: PLC0415 - circular

    title = act.title
    seq = act.next_seq
    user = await identify_caller(request)
    receipt: dict[str, Any] = {
        "index": index,
        "action_key": act.action_key,
        "tool_name": act.tool_name,
        "title": title,
        "finding_case": True,
        "finding": case.identity,
    }

    state = await _finding_state(request, act, case)
    if state.case_id:
        detail = _already_on_case_sentence(state.case_id)
        await _persist_action_executed(
            request,
            act.inv_real_id,
            act.next_seq,
            {
                **receipt,
                "success": True,
                "by": user,
                "note": "already_escalated",
                "case_id": state.case_id,
                "detail": detail,
            },
        )
        # The press wrote nothing, so the row reads it in the info tone.
        return ExecuteActionResult(status="executed", title=title, detail=detail, count=0)
    if state.open_intent is not None:
        if not retry:
            return ExecuteActionResult(
                status="error", title=title, error=_open_intent_sentence(case)
            )
        cleared = await _clear_open_intent(
            request,
            act,
            case,
            state.open_intent,
            session_id=f"action:{inv_id}",
            sequence=seq,
            user=user,
            receipt=receipt,
        )
        if not cleared:
            return ExecuteActionResult(
                status="error",
                title=title,
                error="soc-ai could not record the retry, so it opened no case. Try again.",
            )
        seq += 1

    plan = await _finding_attach_plan(request, case)
    if plan is None:
        raise HTTPException(
            status_code=_BLOCK_STATUS[action_rules.CODE_ANCHOR_UNREAD],
            detail={
                "reason": action_rules.CODE_ANCHOR_UNREAD,
                "hint": action_rules.FINDING_UNREAD,
                "tool": act.tool_name,
            },
        )
    skipped = plan.skipped
    claimed: list[str] = []
    if plan.attach:
        reserved = await _reserve(request, elastic, settings, plan.attach, caller=user)
        claimed = [a for a in plan.attach if a in set(reserved.claimed)]
        skipped += len(plan.attach) - len(claimed)

    intent_id = uuid4().hex
    intent = {
        **receipt,
        "phase": "intent",
        "intent_id": intent_id,
        "success": False,
        "by": user,
        "at": _now_iso(),
        "case_title": case.title,
    }
    if not await _record_intent(request, act.inv_real_id, seq, intent):
        return ExecuteActionResult(
            status="error",
            title=title,
            error="soc-ai could not record the press, so it opened no case. Try again.",
        )

    result, error = await execute_write_tool(
        FINDING_CASE_TOOL,
        {"case_title": case.title, "case_description": case.description, "alert_ids": claimed},
        auth=request.app.state.auth,
        settings=request.app.state.settings,
        audit=request.app.state.audit,
        session_id=f"action:{inv_id}",
        user=user,
    )
    result_seq = seq + 1
    settle = {**receipt, "intent_id": intent_id, "by": user}
    if error is not None:
        if _no_case_was_opened(error):
            # Security Onion refused the create, or the call never left. The
            # intent is settled as failed, and the next press can run.
            await _persist_action_executed(
                request,
                act.inv_real_id,
                result_seq,
                {**settle, "phase": "failed", "success": False, "detail": error},
            )
            return ExecuteActionResult(status="error", title=title, error=error)
        # The call may have reached Security Onion. The intent stays open.
        return ExecuteActionResult(
            status="error", title=title, error=f"{error} {_open_intent_sentence(case)}"
        )
    body = result if isinstance(result, dict) else {}
    case_id = _case_id_from_result(body)
    if not case_id:
        # Security Onion took the create and named no case. The intent stays
        # open: a case exists, and soc-ai cannot name it.
        return ExecuteActionResult(
            status="error",
            title=title,
            error=(
                "Security Onion accepted the case and returned no case id. "
                f"{_open_intent_sentence(case)}"
            ),
        )
    attached = [a for a in (body.get("alerts_attached") or []) if isinstance(a, str)]
    for alert_id in attached:
        await _record_escalation(request, alert_id=alert_id, case_id=case_id, linked=True)
    cited = len(plan.attach) + plan.skipped
    detail = _finding_case_sentence(
        case_id,
        cited=cited,
        attached=len(attached),
        skipped=skipped,
        failed=len(claimed) - len(attached),
    )
    await _persist_action_executed(
        request,
        act.inv_real_id,
        result_seq,
        {
            **settle,
            "phase": "done",
            "success": True,
            "detail": detail,
            "case_id": case_id,
            "alerts_attached": len(attached),
            "alerts_skipped": skipped,
        },
    )
    # One case was opened. The count is the write, like the escalate of an
    # alert: a case that holds no alert is still a case.
    return ExecuteActionResult(status="executed", title=title, detail=detail, count=1)


async def _clear_open_intent(
    request: Request,
    act: _LoadedAction,
    case: _FindingCase,
    open_intent: dict[str, Any],
    *,
    session_id: str,
    sequence: int,
    user: str,
    receipt: dict[str, Any],
) -> bool:
    """Settle an intent with no result as cleared, on the analyst's word. False: not done.

    Two records, in this order, and the press goes on only when both are
    written. The audit record says who cleared the intent of which finding,
    so a second case is never anonymous. The store record settles the intent
    by its id, on whichever run of the finding holds it.
    """
    from soc_ai.audit.logger import AuditWriteError  # noqa: PLC0415 - lazy

    intent_id = open_intent.get("intent_id")
    audit = request.app.state.audit
    if audit is not None:
        try:
            await audit.log_kind(
                session_id,
                "tool_call",
                {
                    "tool": FINDING_CASE_TOOL,
                    "phase": "retry",
                    "finding": case.identity,
                    "cleared_intent": intent_id,
                    "case_title": case.title,
                },
                user=user,
                approved_by=user,
                mutating=True,
            )
        except AuditWriteError:
            _LOGGER.warning("finding case: the retry was not audited", exc_info=True)
            return False
    return await _record_intent(
        request,
        act.inv_real_id,
        sequence,
        {
            **receipt,
            "phase": "cleared",
            "intent_id": intent_id,
            "success": False,
            "by": user,
            "at": _now_iso(),
        },
    )


def _retry_confirm_sentence(case: _FindingCase) -> str:
    """The confirm of "Try again": look first, then press."""
    return (
        "Look at the Cases page of Security Onion first. Press Try again only if no case "
        f'has the title "{case.title}". soc-ai then opens one case and records your name.'
    )


def _no_case_was_opened(error: str) -> bool:
    """Whether a failed write is KNOWN to have opened no case.

    True for an audit abort, where the call never left, for an argument the
    tool refused before any request, and for a create that Security Onion
    answered with a 4xx. A 5xx or a transport fault can follow a create that
    took effect, so those are not known.
    """
    from soc_ai.tools.escalate_to_case import refused_before_a_case  # noqa: PLC0415 - lazy

    return error.startswith("aborted:") or refused_before_a_case(error)


# Per-(inv_id, index) execution locks serialize concurrent execute-action calls
# for the SAME advisory action (double-click, client retry, flaky-network
# auto-retry). Without this, two concurrent escalates both pass the "already
# executed?" idempotency check on the same pre-write snapshot and both POST
# /connect/case → duplicate SO cases (F029 — the very outcome the persisted
# ``action_executed`` marker exists to prevent, but the marker alone only covers
# the reload-replay case, not a concurrent race). Holding the lock across the
# whole handler makes the second caller read the FRESH event stream (with the
# first call's persisted marker) and return ok-with-note instead of writing
# again. A WeakValueDictionary auto-evicts a key's lock once no in-flight call
# references it, so the map can't grow unbounded.
_ACTION_LOCKS: WeakValueDictionary[tuple[str, int], asyncio.Lock] = WeakValueDictionary()


def _action_lock(inv_id: str, index: int) -> asyncio.Lock:
    """The shared ``asyncio.Lock`` for one ``(investigation, action index)``.

    Safe under single-threaded asyncio: the get-or-create never awaits, so two
    coroutines racing for the same key can't interleave and always receive the
    SAME lock object.
    """
    key = (inv_id, index)
    lock = _ACTION_LOCKS.get(key)
    if lock is None:
        lock = asyncio.Lock()
        _ACTION_LOCKS[key] = lock
    return lock


@dataclass(frozen=True)
class _LoadedAction:
    """One recommended action and the run it belongs to, read under one session."""

    inv_real_id: str
    alert_es_id: str | None
    rule_name: str | None
    # The headline of the run: the one sentence the list row shows.
    headline: str | None
    events: list[Any]
    next_seq: int
    anchors_a_hunt: bool
    # What the action rule reads about the run (:mod:`action_rules`).
    facts: action_rules.ActionFacts
    # The case a promoted finding opens, from the stored finding. None on
    # every other run.
    finding_case: _FindingCase | None
    rec: dict[str, Any]
    action_key: str
    tool_name: str
    title: str


async def _load_action(request: Request, inv_id: str, index: int) -> _LoadedAction:
    """Read the run and its ``index``-th recommended action, or raise 404."""
    async with request.app.state.db_sessionmaker() as db:
        got = await inv_svc.get_with_events(db, inv_id)
        if got is None:
            by_alert = await inv_svc.latest_for_alerts(db, [inv_id])
            inv0 = by_alert.get(inv_id)
            if inv0 is not None:
                got = await inv_svc.get_with_events(db, inv0.id)
        if got is None:
            raise HTTPException(status_code=404, detail={"reason": "not_found"})
        inv, events = got
        report = inv.report or {}
        alert_es_id = inv.alert_es_id
        # Anchor-keyed hunt check: a fresh non-hunt row over a promoted
        # finding's or lead's anchor (a POST /investigate re-run) must not
        # launder the document past the kind-keyed guard below — the anchor
        # can be cited telemetry with no SO alert behind it, whatever THIS
        # row's kind says. The grid says below whether it is an alert.
        promoted = action_rules.promoted_kind(inv)
        anchor = (
            (await inv_svc.hunt_anchor_kinds(db, [alert_es_id])).get(alert_es_id)
            if alert_es_id and not promoted
            else None
        )
        # Every action route refuses a replay: the execute, the scope and the
        # dismissal. A replay's actions are closed on the page.
        _refuse_a_replay(inv)
        await _refuse_a_superseded_run(db, inv)
        analyst = (
            (await inv_svc.analyst_verdicts_for_alerts(db, [alert_es_id])).get(alert_es_id)
            if alert_es_id and not inv_svc.is_hunt_subject(inv)
            else None
        )
        finding_case = (
            await _finding_case(db, inv) if promoted == action_rules.ANCHOR_FINDING else None
        )
        mark = (await authorized_svc.marks_for(db, [inv.authorization_id])).get(
            inv.authorization_id or 0
        )
        campaign = (await campaign_svc.links_of(db, [inv.id])).get(inv.id)
    # The grid read waits until the store session is closed. A real alert
    # that a promotion anchors takes the write (dogfood 2026-10-21).
    anchor_status = (
        (await anchor_check.alert_status(request.app.state, [alert_es_id])).get(
            alert_es_id, anchor_check.UNKNOWN
        )
        if anchor is not None and alert_es_id
        else anchor_check.NOT_ALERT
    )
    anchors_a_hunt = promoted is not None or (
        anchor is not None and anchor_status != anchor_check.ALERT
    )
    facts = action_rules.ActionFacts(
        promoted=promoted,
        anchor=anchor,
        anchor_status=anchor_status,
        alert_id=alert_es_id,
        run_verdict=inv.verdict,
        analyst_verdict=analyst.verdict if analyst is not None else None,
        analyst_by=analyst.resolved_by if analyst is not None else None,
        case_id=_observed_case_id(list(events)),
        authorized=mark.label if mark is not None and mark.holds else None,
    )
    # The campaign that holds the run. The action stays executable.
    facts = action_rules.with_campaign(facts, campaign)
    recs = report.get("recommended_actions") or []
    if index < 0 or index >= len(recs):
        raise HTTPException(status_code=404, detail={"reason": "no_such_action"})
    rec = recs[index]
    tool_name = rec.get("tool_name", "")
    return _LoadedAction(
        inv_real_id=inv.id,
        alert_es_id=alert_es_id,
        rule_name=inv.rule_name,
        headline=inv.rationale,
        events=list(events),
        next_seq=max((e.sequence for e in events), default=0) + 1,
        anchors_a_hunt=anchors_a_hunt,
        facts=facts,
        finding_case=finding_case,
        rec=rec,
        # Idempotency identity is the action's CONTENT, not its list position: a
        # chat-resolve can replace recommended_actions and shift indexes (F04).
        action_key=_action_identity(rec),
        tool_name=tool_name,
        title=_ACTION_TITLE.get(tool_name, tool_name or "Action"),
    )


class ExecuteActionIn(BaseModel):
    """What the analyst confirmed. ``group`` is the plan the card stated;
    ``alert`` is "Acknowledge this alert only". Only an ack reads it."""

    scope: Literal["group", "alert"] = "group"
    # "Try again" on the case of a finding whose earlier press recorded no
    # result. The analyst confirmed that Security Onion holds no case with the
    # title. Only that state reads it.
    retry: bool = False


@router.post(
    "/investigations/{inv_id}/actions/{index}/execute",
    response_model=ExecuteActionResult,
)
async def execute_action(
    request: Request,
    inv_id: str,
    index: int,
    body: ExecuteActionIn | None = None,
    settings: Settings = Depends(get_settings_dep),
    elastic: ElasticClient = Depends(get_elastic),
) -> ExecuteActionResult:
    """Execute one report-recommended write action against Security Onion.

    ``index`` is the position in ``report.recommended_actions`` (the SPA's
    advisory action cards are built in that order). This is the single
    analyst write path — the report recommends, the analyst executes here.

    Idempotent: a previously executed action (persisted ``action_executed``
    event) or an ack of an already-acked alert returns ok-with-note instead of
    writing again — no duplicate SO cases, no double acks. Concurrent executes of
    the same action are serialized (F029) so a double-click can't race the write.
    """
    # Serialize per (inv_id, index): a second concurrent caller blocks here, then
    # re-reads the event stream inside `_execute_action_locked` and sees the first
    # call's persisted marker — so it never fires a duplicate write.
    async with _action_lock(inv_id, index):
        return await _execute_action_locked(
            request,
            inv_id=inv_id,
            index=index,
            scope=(body or ExecuteActionIn()).scope,
            retry=(body or ExecuteActionIn()).retry,
            settings=settings,
            elastic=elastic,
        )


def _bound_tool_args(act: _LoadedAction) -> dict[str, Any]:
    """The arguments of the write, with its target bound on the server.

    SECURITY (F07): the write TARGET is bound server-side, never taken from the
    model. ``RecommendedAction.tool_args`` is fully model-authored (no
    validator) and assembled from attacker-influenceable enriched-alert context,
    so a present-but-wrong alert_id/case_id would ack/escalate/comment on a
    DIFFERENT SO object than the one the analyst approved in this investigation.
    """
    tool_name = act.tool_name
    # A stored report is not schema-checked on read. Arguments that are not an
    # object count as no arguments.
    stored_args = act.rec.get("tool_args")
    tool_args = dict(stored_args) if isinstance(stored_args, dict) else {}
    if tool_name in ("ack_alert", "escalate_to_case"):
        # Always OVERWRITE (not default-when-missing): the target is this
        # investigation's own alert, even when the model supplied an alert_id.
        if not act.alert_es_id:
            raise HTTPException(
                status_code=400,
                detail={"reason": "missing_alert_id", "tool": tool_name},
            )
        tool_args["alert_id"] = act.alert_es_id
        if tool_name == "escalate_to_case":
            _bind_case_text(
                tool_args,
                inv_id=act.inv_real_id,
                rule_name=act.rule_name,
                headline=act.headline,
                rationale=act.rec.get("rationale"),
            )
    elif tool_name == "add_case_comment":
        # Bind to a case THIS investigation itself opened (a prior escalate the
        # system executed and observed), never the model's free-form case_id. No
        # such case → refuse rather than comment on an arbitrary/hostile case id.
        bound_case_id = _observed_case_id(act.events)
        if not bound_case_id:
            raise HTTPException(
                status_code=400,
                detail={"reason": "no_case_for_comment", "tool": tool_name},
            )
        tool_args["case_id"] = bound_case_id
    return tool_args


def _refuse_a_replay(inv: Investigation) -> None:
    """Refuse every write a backtest replay recommends.

    A backtest replay is a measurement on an alert an analyst already closed.
    Its recommendations are part of what the backtest measured, and none of
    them is a write to make. The detail page closes every action of a replay.
    This refusal holds for a client that skips the page.
    """
    if inv_svc.is_backtest(inv):
        raise HTTPException(
            status_code=400,
            detail={
                "reason": "backtest_replay",
                "hint": (
                    "This investigation is a backtest replay. soc-ai executes no action for a "
                    "replay. Open the live investigation of the alert to act on it."
                ),
            },
        )


async def _refuse_a_superseded_run(db: Any, inv: Investigation) -> None:
    """Refuse every action route on a run that a newer run replaced.

    The page of a replaced run locks every action. The Investigations list
    offers Execute and Dismiss on the row, and a row read before a newer run
    started still offers them (dogfood 2026-10-19, R1-I1). This refusal holds
    for a stale row and for a client that skips the page. The rule is the
    detail page's, the one the override route reads.
    """
    from soc_ai.api.webui.routes_investigations import (  # noqa: PLC0415 - route cycle
        superseding_run_id,
    )

    newer = await superseding_run_id(db, inv)
    if newer:
        raise HTTPException(
            status_code=409,
            detail={
                "reason": "superseded",
                "invId": newer,
                "hint": f"Investigation {newer} replaced this one. Act on that investigation.",
            },
        )


async def _execute_action_locked(
    request: Request,
    *,
    inv_id: str,
    index: int,
    scope: str = "group",
    retry: bool = False,
    settings: Settings,
    elastic: ElasticClient,
) -> ExecuteActionResult:
    """Execute the write action. MUST run under ``_action_lock(inv_id, index)``.

    The event stream (carrying the ``action_executed`` idempotency marker) is read
    AFTER the caller acquired the lock, so a concurrent double-click can't pass the
    "already executed?" check on a stale pre-write snapshot.
    """
    act = await _load_action(request, inv_id, index)
    events, action_key, tool_name, title = act.events, act.action_key, act.tool_name, act.title
    alert_es_id, inv_real_id, next_seq = act.alert_es_id, act.inv_real_id, act.next_seq
    if tool_name not in WRITE_TOOLS:
        raise HTTPException(
            status_code=400,
            detail={"reason": "not_executable", "tool": tool_name},
        )

    # The one action rule, the one the card, the list row and the needs-you
    # count read (V3-N2). A promoted finding's anchor is cited telemetry, not
    # an SO alert: there is nothing to ack/escalate, and the rule-keyed group
    # ack below must never see a finding title as a rule_name. The anchor rule
    # keys off the ANCHOR document (any promoted investigation over this
    # alert_es_id), not just this row's own kind. A write never acts against
    # an analyst verdict. The demo guard refuses every write before this.
    block = action_rules.action_block(act.facts, tool_name)
    if block is not None:
        refusal: dict[str, Any] = {"reason": block.code, "hint": block.reason, "tool": tool_name}
        if block.code == action_rules.CODE_CAMPAIGN:
            refusal["href"] = f"/campaigns/{act.facts.campaign_id}"
        raise HTTPException(status_code=_BLOCK_STATUS.get(block.code, 400), detail=refusal)

    # "Acknowledge this alert only" acts on the grid state, not on the record:
    # an earlier group ack can leave this alert open (dogfood 2026-10-06, S3),
    # and an ack of one alert is idempotent. Every other press checks the record.
    only_this_alert = tool_name == "ack_alert" and scope == "alert"

    # Already executed through this endpoint? Never write twice (the escalate
    # case would open a duplicate SO case) — confirm instead.
    executed = _executed_actions(events)
    if not only_this_alert and (action_key in executed or f"#idx:{index}" in executed):
        return ExecuteActionResult(
            status="executed",
            title=title,
            detail="Already executed. soc-ai did not repeat it.",
        )

    if action_rules.opens_finding_case(act.facts, tool_name):
        # A promoted finding: the case comes from the stored finding, and no
        # argument of the model is read.
        return await _open_finding_case(
            request,
            act,
            inv_id=inv_id,
            index=index,
            retry=retry,
            settings=settings,
            elastic=elastic,
        )

    tool_args = _bound_tool_args(act)

    user = await identify_caller(request)
    receipt: dict[str, Any] = {
        "index": index,
        "action_key": action_key,
        "tool_name": tool_name,
        "title": title,
    }

    # Group-scoped ack (rule-keyed): the analyst's intent is "this detection is
    # handled", not "ack one event of it" — a single-event ack left the rest of
    # the group in the queue after a successful "Executed ✓". Falls back to the
    # single-alert ack when the run has no rule_name or the group fetch fails.
    if tool_name == "ack_alert" and act.rule_name and not only_this_alert:
        from soc_ai.api.webui.routes_alert_actions import _ack_many  # noqa: PLC0415

        plan = await _group_ack_plan(
            request,
            rule_name=act.rule_name,
            settings=settings,
            elastic=elastic,
            own_alert_id=alert_es_id,
        )
        if plan is not None:
            if not plan.ids:
                # Every alert the window holds waits on a person. Nothing was
                # written, so nothing is recorded and the card stays open.
                return ExecuteActionResult(
                    status="executed", title=title, detail=_ack_scope_sentence(plan), count=0
                )
            acked, failed = await _ack_many(
                request,
                plan.ids,
                session_id=f"action-ack-group:{act.rule_name}",
                caller=user,
            )
            detail = _ack_done_sentence(plan, acked, failed)
            if acked == 0:
                return ExecuteActionResult(status="error", title=title, error=detail, count=0)
            await _persist_action_executed(
                request,
                inv_real_id,
                next_seq,
                {
                    **receipt,
                    "success": True,
                    "by": user,
                    "detail": detail,
                    "group": True,
                    "acked": acked,
                    "held": plan.held,
                },
            )
            return ExecuteActionResult(status="executed", title=title, detail=detail, count=acked)

    # Acking an alert that is ALREADY acked in SO (group-ack, auto-ack of
    # another run, the SO web UI): ok-with-note, and persist the execution so
    # the card reads applied from now on. ES-error fallback inside the helper
    # means a probe failure just runs the (harmless, idempotent) ack as before.
    if tool_name == "ack_alert" and await _timeline._alert_currently_acked(
        elastic, settings, tool_args.get("alert_id") or alert_es_id
    ):
        await _persist_action_executed(
            request,
            inv_real_id,
            next_seq,
            {**receipt, "success": True, "by": user, "note": "already_acknowledged"},
        )
        return ExecuteActionResult(
            status="executed",
            title=title,
            detail="This alert is already acknowledged in Security Onion.",
            count=0,
        )

    if tool_name == "escalate_to_case":
        # Reserve the alert BEFORE opening the case, so a group escalate racing
        # this press collides on the ledger's unique index instead of on
        # Security Onion's case queue. See _reserve_escalate.
        refused = await _reserve_escalate(
            request,
            elastic,
            settings,
            str(tool_args["alert_id"]),
            user=user,
            inv_real_id=inv_real_id,
            sequence=next_seq,
            receipt={**receipt, "note": "already_escalated"},
        )
        if refused is not None:
            return refused

    result, error = await execute_write_tool(
        tool_name,
        tool_args,
        auth=request.app.state.auth,
        settings=request.app.state.settings,
        audit=request.app.state.audit,
        session_id=f"action:{inv_id}",
        user=user,
    )
    if error is not None:
        return ExecuteActionResult(status="error", title=title, error=error)
    detail = _action_detail(tool_name, result)
    # An escalate that put the alert on no case is a failed escalate, whatever
    # Security Onion answered the case create with. It decides the status, the
    # persisted receipt and which ledger row is written.
    escalated = tool_name != "escalate_to_case" or _escalate_outcome(result)[0]
    exec_payload: dict[str, Any] = {
        **receipt,
        "success": escalated,
        "by": user,
        "detail": detail,
    }
    if only_this_alert:
        exec_payload["scope"] = "alert"
    if tool_name == "escalate_to_case":
        # Persist the SO-created case id so a later add_case_comment can bind its
        # write target to a case THIS investigation opened (F07). Recorded on an
        # unattached case too, so the empty case an operator has to deal with is
        # not only in a response they may have navigated away from. The
        # success=False on the receipt keeps it out of _observed_case_id.
        case_id = _case_id_from_result(result)
        if case_id:
            exec_payload["case_id"] = case_id
        await _record_escalation(
            request,
            alert_id=tool_args.get("alert_id"),
            case_id=case_id,
            linked=escalated,
        )
    await _persist_action_executed(request, inv_real_id, next_seq, exec_payload)
    if not escalated:
        return ExecuteActionResult(status="error", title=title, error=detail)
    return ExecuteActionResult(
        status="executed",
        title=title,
        detail=detail,
        count=1 if tool_name in ("ack_alert", "escalate_to_case") else None,
    )


# ── What a write will do, before the click ─────────────────────────────────


class ActionScopeOut(BaseModel):
    """What one recommended action will write, stated before the analyst confirms.

    ``scope`` is "group" for a rule-wide ack, "alert" for a write to the one
    alert of this run, "finding" for the case of a promoted finding, and
    "case" for a comment on the case this run opened.
    ``count`` and ``hosts`` are None when the grid did not answer.
    """

    tool: str
    scope: str
    count: int | None = None
    hosts: int | None = None
    held: int = 0
    rangeLabel: str = ""
    sentence: str
    # An escalate only: the cases the alert is already on. The press then
    # opens no second case (V3-N2). ``casesComplete`` is False when the grid
    # did not confirm the list.
    cases: list[_timeline.CaseRefOut] = []
    casesComplete: bool = False
    # The case of a finding only: an earlier press recorded no result, so a
    # press opens no case. The card then offers "Try again" behind a confirm
    # that reads ``retrySentence``.
    retry: bool = False
    retrySentence: str | None = None


_ALERT_ONLY_ACK = "Acknowledge this alert in Security Onion."
_ESCALATE_SENTENCE = "Open one Security Onion case for this alert."
_FINDING_CASE_SENTENCE = "Open one Security Onion case for this finding."
_COMMENT_SENTENCE = "Add a comment to the Security Onion case this investigation opened."
_NO_SECOND_CASE = "soc-ai opens no second case."


async def _finding_scope(
    request: Request, act: _LoadedAction, case: _FindingCase
) -> ActionScopeOut:
    """What the escalate of a finding will write: one case, and the alerts it attaches.

    ``count`` is the alerts the press attaches and marks, and ``held`` is the
    cited alerts it skips. The press reads the same record and the same plan.
    The grid can move between the two reads, and the receipt then states the
    real counts.
    """
    state = await _finding_state(request, act, case)
    if state.case_id:
        return ActionScopeOut(
            tool=act.tool_name,
            scope="finding",
            count=0,
            sentence=_already_on_case_sentence(state.case_id),
        )
    if state.open_intent is not None:
        return ActionScopeOut(
            tool=act.tool_name,
            scope="finding",
            count=0,
            sentence=_open_intent_sentence(case),
            retry=True,
            retrySentence=_retry_confirm_sentence(case),
        )
    plan = await _finding_attach_plan(request, case)
    if plan is None:
        return ActionScopeOut(
            tool=act.tool_name,
            scope="finding",
            sentence=f"{_FINDING_CASE_SENTENCE} {action_rules.FINDING_UNREAD}",
        )
    return ActionScopeOut(
        tool=act.tool_name,
        scope="finding",
        count=len(plan.attach),
        held=plan.skipped,
        sentence=_finding_scope_sentence(plan),
    )


def cases_sentence(case_ids: list[str], *, complete: bool) -> str:
    """Where the alert already is: "The alert is already on cases A, B."

    A list the grid did not confirm names its cases as a finding, like the
    Alerts escalate confirm: "soc-ai found the alert on case A."
    """
    noun = "case" if len(case_ids) == 1 else "cases"
    joined = ", ".join(case_ids)
    if complete:
        return f"The alert is already on {noun} {joined}."
    return f"soc-ai found the alert on {noun} {joined}."


@router.get(
    "/investigations/{inv_id}/actions/{index}/scope",
    response_model=ActionScopeOut,
)
async def action_scope(
    request: Request,
    inv_id: str,
    index: int,
    settings: Settings = Depends(get_settings_dep),
    elastic: ElasticClient = Depends(get_elastic),
) -> ActionScopeOut:
    """What the ``index``-th action will write, in the words the card shows.

    The ack plan is the one the execute route then writes, from the same
    helper, so the count on the card is the count of the write. The grid can
    move between the two reads. The receipt then states the real count.
    """
    act = await _load_action(request, inv_id, index)
    if action_rules.opens_finding_case(act.facts, act.tool_name) and act.finding_case is not None:
        return await _finding_scope(request, act, act.finding_case)
    if act.tool_name == "escalate_to_case":
        # The cases the alert is already on, from the sources the execute
        # route asks before it opens a case. A promotion names cited
        # telemetry, and no case read applies to it.
        case_ids, complete = (
            await case_links.cases_of_alert(
                request.app.state.db_sessionmaker, elastic, settings, act.alert_es_id
            )
            if act.alert_es_id and act.facts.promoted is None
            else ([], False)
        )
        if case_ids:
            return ActionScopeOut(
                tool=act.tool_name,
                scope="alert",
                count=0,
                sentence=f"{cases_sentence(case_ids, complete=complete)} {_NO_SECOND_CASE}",
                cases=[
                    _timeline.CaseRefOut(id=c, url=case_links.case_url(settings, c))
                    for c in case_ids
                ],
                casesComplete=complete,
            )
        return ActionScopeOut(
            tool=act.tool_name, scope="alert", count=1, sentence=_ESCALATE_SENTENCE
        )
    if act.tool_name == "add_case_comment":
        return ActionScopeOut(tool=act.tool_name, scope="case", sentence=_COMMENT_SENTENCE)
    if act.tool_name != "ack_alert" or act.anchors_a_hunt:
        raise HTTPException(
            status_code=400,
            detail={"reason": "not_executable", "tool": act.tool_name},
        )
    plan = (
        await _group_ack_plan(
            request,
            rule_name=act.rule_name,
            settings=settings,
            elastic=elastic,
            own_alert_id=act.alert_es_id,
        )
        if act.rule_name
        else None
    )
    if plan is None:
        return ActionScopeOut(tool=act.tool_name, scope="alert", count=1, sentence=_ALERT_ONLY_ACK)
    return ActionScopeOut(
        tool=act.tool_name,
        scope="group",
        count=len(plan.ids),
        hosts=plan.hosts,
        held=plan.held,
        rangeLabel=_GROUP_ACK_RANGE_LABEL,
        sentence=_ack_scope_sentence(plan),
    )


# ── Dismiss a recommendation, and undo it ──────────────────────────────────


class ActionDismissOut(BaseModel):
    dismissed: bool
    by: str
    at: str


async def _record_dismissal(
    request: Request, inv_id: str, index: int, *, kind: str
) -> ActionDismissOut:
    """Store a dismissal (or its undo) of one recommendation, with the actor and time.

    Dismiss changed the card in one tab and nowhere else: a reload, a second
    tab or the next analyst saw the action pending again (dogfood 2026-10-06,
    first hour S4). The record is an investigation event, keyed on the
    action's identity like the execute receipt, so it follows the action
    across a chat-resolve re-index.
    """
    async with _action_lock(inv_id, index):
        act = await _load_action(request, inv_id, index)
        executed = _executed_actions(act.events)
        if act.action_key in executed or f"#idx:{index}" in executed:
            raise HTTPException(
                status_code=409,
                detail={
                    "reason": "already_executed",
                    "hint": "soc-ai already executed this action. You cannot dismiss it.",
                },
            )
        user = await identify_caller(request)
        at = _now_iso()
        async with request.app.state.db_sessionmaker() as db:
            await inv_svc.append_events(
                db,
                act.inv_real_id,
                [
                    dismissal_event(
                        sequence=act.next_seq,
                        kind=kind,
                        index=index,
                        action_key=act.action_key,
                        tool_name=act.tool_name,
                        by=user,
                        at=at,
                    )
                ],
            )
    # A dismissed action changes what waits in a campaign.
    campaign_refresh.request_refresh()
    return ActionDismissOut(dismissed=kind == "action_dismissed", by=user, at=at)


def dismissal_event(
    *,
    sequence: int,
    kind: str,
    index: int,
    action_key: str,
    tool_name: str,
    by: str,
    at: str,
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """The event of a dismissal, ``action_dismissed``, or of its undo, ``action_restored``.

    The dismiss route and the clear of Needs you
    (:mod:`soc_ai.webui.needs_you_clear`) write this one shape, so the action
    card reads both the same. ``extra`` adds keys to the payload: the clear
    adds its reason and its id.
    """
    payload: dict[str, Any] = {
        "index": index,
        "action_key": action_key,
        "tool_name": tool_name,
        "by": by,
        "at": at,
    }
    payload.update(extra or {})
    return {"sequence": sequence, "kind": kind, "payload": payload}


@router.post(
    "/investigations/{inv_id}/actions/{index}/dismiss",
    response_model=ActionDismissOut,
)
async def dismiss_action(request: Request, inv_id: str, index: int) -> ActionDismissOut:
    """Dismiss one recommendation. Nothing is written to Security Onion."""
    return await _record_dismissal(request, inv_id, index, kind="action_dismissed")


@router.post(
    "/investigations/{inv_id}/actions/{index}/restore",
    response_model=ActionDismissOut,
)
async def restore_action(request: Request, inv_id: str, index: int) -> ActionDismissOut:
    """Undo a dismissal. The recommendation is pending again."""
    return await _record_dismissal(request, inv_id, index, kind="action_restored")


# ── Chat verdict resolution ────────────────────────────────────────────────


class ResolveIn(BaseModel):
    message_id: int
    token: str


@router.post("/investigations/{inv_id}/resolve")
async def resolve_investigation(request: Request, inv_id: str, body: ResolveIn) -> dict[str, Any]:
    """Apply a validated chat verdict proposal. Token + message gated, idempotent."""
    # Not owner-scoped: any authenticated caller may apply a proposal, consistent
    # with the action-execute route. The actor is recorded for audit.
    resolved_by = await identify_caller(request)
    async with request.app.state.db_sessionmaker() as db:
        msg = await chat_svc.get_message(db, body.message_id)
        if msg is None or msg.investigation_id != inv_id:
            raise HTTPException(status_code=404, detail={"reason": "proposal_not_found"})
        meta = msg.meta or {}
        if meta.get("kind") != "verdict_proposal" or meta.get("validation") != "pass":
            raise HTTPException(status_code=400, detail={"reason": "not_applyable"})
        if meta.get("token") != body.token:
            raise HTTPException(status_code=403, detail={"reason": "bad_token"})
        if meta.get("applied"):
            raise HTTPException(status_code=409, detail={"reason": "already_applied"})
        proposal = meta.get("proposal") or {}
        verdict = proposal.get("verdict")
        if not verdict:
            raise HTTPException(status_code=400, detail={"reason": "malformed_proposal"})
        # A proposal is model text too. A comment it recommends needs a case
        # that this investigation opened, like a comment in a report.
        actions = proposal.get("recommended_actions")
        if isinstance(actions, list):
            got = await inv_svc.get_with_events(db, inv_id)
            opened = _observed_case_id(list(got[1])) if got is not None else None
            actions, _dropped = drop_case_comments_without_a_case(actions, case_open=bool(opened))
        updated = await inv_svc.resolve(
            db,
            inv_id,
            verdict=verdict,
            confidence=proposal.get("confidence"),
            rationale=proposal.get("rationale"),
            recommended_actions=actions,
            resolved_by=resolved_by,
            source_message_id=body.message_id,
        )
        if updated is None:
            raise HTTPException(status_code=404, detail={"reason": "not_found"})
    return {"ok": True, "verdict": verdict}


# ── Manual verdict override ────────────────────────────────────────────────

_VALID_VERDICTS = {"true_positive", "false_positive", "needs_more_info"}


def _override_headline(user: str, reason: str | None) -> str:
    """The rationale headline after an analyst override.

    The headline used to keep the model's text when the analyst gave no
    reason, and the old benign sentence then stood over a true positive
    (dogfood 2026-10-06, first hour S3).
    """
    text = (reason or "").strip().rstrip(".")
    return f"Verdict set by {user}: {text}." if text else f"Verdict set by {user}."


def _override_actions(
    verdict: str, *, user: str, rule_name: str | None, headline: str
) -> list[dict[str, Any]]:
    """The recommended actions that fit an analyst's verdict.

    A true positive gets one escalate and never an ack. A false positive gets
    one ack. A needs more info verdict gets none: the page offers Request
    more info. The case title and the description are bound here, from the
    rule and the analyst's words, because the escalate needs both.
    """
    if verdict == "true_positive":
        return [
            {
                "tool_name": "escalate_to_case",
                "tool_args": {
                    "case_title": fit_case_title(rule_name or _DEFAULT_CASE_TITLE),
                    "case_description": fit_case_description(headline),
                },
                "rationale": (
                    f"{user} set the verdict to true positive. "
                    "Open a Security Onion case for this alert."
                ),
            }
        ]
    if verdict == "false_positive":
        return [
            {
                "tool_name": "ack_alert",
                "tool_args": {},
                "rationale": f"{user} set the verdict to false positive. Acknowledge the alert.",
            }
        ]
    return []


class OverrideVerdictIn(BaseModel):
    verdict: str
    rationale: str | None = None
    confidence: float | None = Field(default=None, ge=0.0, le=1.0)


@router.post("/investigations/{inv_id}/override")
async def override_verdict(
    request: Request, inv_id: str, body: OverrideVerdictIn
) -> dict[str, Any]:
    """Manually override a completed investigation's verdict with analyst provenance."""
    if body.verdict not in _VALID_VERDICTS:
        valid = sorted(_VALID_VERDICTS)
        raise HTTPException(
            status_code=400,
            detail={
                "reason": "invalid_verdict",
                "valid": valid,
                "hint": f"verdict accepts one of these values: {', '.join(valid)}.",
            },
        )
    resolved_by = await identify_caller(request)
    async with request.app.state.db_sessionmaker() as db:
        inv = await db.get(Investigation, inv_id)
        if inv is None:
            raise HTTPException(status_code=404, detail={"reason": "not_found"})
        if inv.status == "running":
            raise HTTPException(
                status_code=409,
                detail={
                    "reason": "investigation_running",
                    "hint": "Wait for the investigation to complete before you override.",
                },
            )
        from soc_ai.api.webui.routes_investigations import (  # noqa: PLC0415 - route cycle
            superseding_run_id,
        )

        newer = await superseding_run_id(db, inv)
        if newer:
            # A record keeps the verdict it reached. An override on it changed
            # the verdict of a run the alert no longer stands on, and the
            # alert row never showed it (dogfood 2026-10-19, R2-D4).
            raise HTTPException(
                status_code=409,
                detail={
                    "reason": "superseded",
                    "invId": newer,
                    "hint": f"Investigation {newer} replaced this one. Override that one.",
                },
            )
        headline = _override_headline(resolved_by, body.rationale)
        updated = await inv_svc.resolve(
            db,
            inv_id,
            verdict=body.verdict,
            confidence=body.confidence if body.confidence is not None else 1.0,
            rationale=headline,
            # The actions follow the new verdict. A true positive kept the
            # model's "Acknowledge alert" and its benign reason.
            recommended_actions=_override_actions(
                body.verdict, user=resolved_by, rule_name=inv.rule_name, headline=headline
            ),
            resolved_by=resolved_by,
            resolved_via="manual",
            source_message_id=None,
        )
        if updated is None:
            raise HTTPException(status_code=404, detail={"reason": "not_found"})
    return {
        "ok": True,
        "verdict": body.verdict,
        "confidence": updated.confidence,
        "resolvedBy": resolved_by,
    }
