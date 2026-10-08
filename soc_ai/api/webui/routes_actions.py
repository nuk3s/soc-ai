"""Verdict/action mutations: execute-action, resolve, override."""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass
from typing import Any, Literal
from weakref import WeakValueDictionary

from fastapi import Depends, HTTPException, Request
from pydantic import BaseModel, Field

from soc_ai.api.deps import get_elastic, get_settings_dep
from soc_ai.api.security import identify_caller
from soc_ai.api.webui import _timeline
from soc_ai.api.webui._shared import (
    _iso_utc,
    router,
)
from soc_ai.api.webui._timeline import (
    _ACTION_TITLE,
    _action_identity,
    _executed_actions,
)
from soc_ai.config import Settings
from soc_ai.so_client.elastic import ElasticClient
from soc_ai.store import chat as chat_svc
from soc_ai.store import escalations as esc_svc
from soc_ai.store import investigations as inv_svc
from soc_ai.store.auth import utcnow
from soc_ai.store.models import Investigation
from soc_ai.tools.write_exec import WRITE_TOOLS, execute_write_tool
from soc_ai.webui import alerts_query as aq

_LOGGER = logging.getLogger(__name__)

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
    """The SO case id THIS investigation itself opened, if any.

    Scans persisted successful ``action_executed`` events for an
    ``escalate_to_case`` execution and returns the case id the system observed
    from SO's response (persisted as ``case_id``). This is the ONLY case id an
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
    await _persist_action_executed(
        request, inv_real_id, sequence, {**receipt, "success": True, "by": user}
    )
    return ExecuteActionResult(
        status="executed",
        title=title,
        detail="This alert is already on a Security Onion case. soc-ai opened no second case.",
    )


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
    events: list[Any]
    next_seq: int
    anchors_a_hunt: bool
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
        # launder the document past the kind-keyed guard below — the anchor is
        # still cited telemetry with no SO alert behind it, whatever THIS
        # row's kind says.
        anchors_a_hunt = inv_svc.is_promoted(inv) or (
            alert_es_id is not None and bool(await inv_svc.hunt_anchor_ids(db, [alert_es_id]))
        )
        # Every action route refuses a replay: the execute, the scope and the
        # dismissal. A replay's actions are closed on the page.
        _refuse_a_replay(inv)
    recs = report.get("recommended_actions") or []
    if index < 0 or index >= len(recs):
        raise HTTPException(status_code=404, detail={"reason": "no_such_action"})
    rec = recs[index]
    tool_name = rec.get("tool_name", "")
    return _LoadedAction(
        inv_real_id=inv.id,
        alert_es_id=alert_es_id,
        rule_name=inv.rule_name,
        events=list(events),
        next_seq=max((e.sequence for e in events), default=0) + 1,
        anchors_a_hunt=anchors_a_hunt,
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
            settings=settings,
            elastic=elastic,
        )


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
                    "This run is a backtest replay. soc-ai executes no action for a "
                    "replay. Open the live investigation of the alert to act on it."
                ),
            },
        )


async def _execute_action_locked(  # noqa: PLR0915 — linear single-analyst write path
    request: Request,
    *,
    inv_id: str,
    index: int,
    scope: str = "group",
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

    if act.anchors_a_hunt:
        # A promoted finding's anchor is cited telemetry, not an SO alert —
        # there is nothing to ack/escalate, and the rule-keyed group ack below
        # must never see a finding title as a rule_name. Keyed off the ANCHOR
        # document (any hunt-kind investigation over this alert_es_id), not
        # just this row's own kind — see anchors_a_hunt above. No `and
        # tool_name in WRITE_TOOLS` conjunct here: the check above already
        # 400s any non-write tool, so by this point tool_name is proven to be
        # a write tool — restating the condition would just be dead weight.
        raise HTTPException(
            status_code=400,
            detail={
                "reason": "hunt_kind_no_so_target",
                "hint": "A promoted finding has no Security Onion alert to act on.",
            },
        )

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

    tool_args = dict(act.rec.get("tool_args") or {})
    # SECURITY (F07): the write TARGET is bound server-side, never taken from the
    # model. ``RecommendedAction.tool_args`` is fully model-authored (no
    # validator) and assembled from attacker-influenceable enriched-alert context,
    # so a present-but-wrong alert_id/case_id would ack/escalate/comment on a
    # DIFFERENT SO object than the one the analyst approved in this investigation.
    if tool_name in ("ack_alert", "escalate_to_case"):
        # Always OVERWRITE (not default-when-missing): the target is this
        # investigation's own alert, even when the model supplied an alert_id.
        if not alert_es_id:
            raise HTTPException(
                status_code=400,
                detail={"reason": "missing_alert_id", "tool": tool_name},
            )
        tool_args["alert_id"] = alert_es_id
    elif tool_name == "add_case_comment":
        # Bind to a case THIS investigation itself opened (a prior escalate the
        # system executed and observed), never the model's free-form case_id. No
        # such case → refuse rather than comment on an arbitrary/hostile case id.
        bound_case_id = _observed_case_id(events)
        if not bound_case_id:
            raise HTTPException(
                status_code=400,
                detail={"reason": "no_case_for_comment", "tool": tool_name},
            )
        tool_args["case_id"] = bound_case_id

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
    alert of this run, and "case" for a comment on the case this run opened.
    ``count`` and ``hosts`` are None when the grid did not answer.
    """

    tool: str
    scope: str
    count: int | None = None
    hosts: int | None = None
    held: int = 0
    rangeLabel: str = ""
    sentence: str


_ALERT_ONLY_ACK = "Acknowledge this alert in Security Onion."
_ESCALATE_SENTENCE = "Open one Security Onion case for this alert."
_COMMENT_SENTENCE = "Add a comment to the Security Onion case this investigation opened."


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
    if act.tool_name == "escalate_to_case":
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
                    {
                        "sequence": act.next_seq,
                        "kind": kind,
                        "payload": {
                            "index": index,
                            "action_key": act.action_key,
                            "tool_name": act.tool_name,
                            "by": user,
                            "at": at,
                        },
                    }
                ],
            )
    return ActionDismissOut(dismissed=kind == "action_dismissed", by=user, at=at)


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
        updated = await inv_svc.resolve(
            db,
            inv_id,
            verdict=verdict,
            confidence=proposal.get("confidence"),
            rationale=proposal.get("rationale"),
            recommended_actions=proposal.get("recommended_actions"),
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
                    "case_title": rule_name or "soc-ai investigation",
                    "case_description": headline,
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
