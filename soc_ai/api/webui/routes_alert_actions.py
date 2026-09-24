"""Alert mutations: ack-group, escalate-group, ack-events, assign."""

from __future__ import annotations

import asyncio
import logging
from datetime import UTC, datetime
from typing import Annotated, Any

from elastic_transport import TransportError
from elasticsearch import ApiError
from fastapi import Depends, HTTPException, Request
from pydantic import BaseModel, Field, field_validator

from soc_ai.api.deps import get_elastic, get_settings_dep
from soc_ai.api.security import identify_caller
from soc_ai.api.webui._shared import (
    _iso_z,
    router,
)
from soc_ai.api.webui.routes_alerts import _es_api_error_http, _grid_unavailable
from soc_ai.config import Settings
from soc_ai.errors import OqlValidationError
from soc_ai.so_client.elastic import ElasticClient
from soc_ai.store import assignments as assign_svc
from soc_ai.store import escalations as esc_svc
from soc_ai.store import investigations as inv_svc
from soc_ai.tools.write_exec import execute_write_tool
from soc_ai.webui import alerts_query as aq
from soc_ai.webui.case_links import case_ids_for_alerts

_LOGGER = logging.getLogger(__name__)

# One BELOW ``aq.MAX_EVENTS`` so ``ack_group`` can collect ``_ACK_CAP + 1``
# unacknowledged events and actually observe the overflow: a cap EQUAL to the
# page size made ``capped`` unreachable (a >200-event group was silently
# part-acked with ``capped=false``, F21).
_ACK_CAP = 199  # maximum events acknowledged per ack-group call
_ACK_CONCURRENCY = 8  # bounded fan-out for bulk ack to keep ES/SO round-trips parallel-but-capped

# How far :func:`_scan_group` will page looking for events that still
# need the write. It only pages at all on a grid that cannot hide an
# acknowledged event from a query, where every press would otherwise re-read
# the same first page forever; each page is a size-200 search costing
# milliseconds, so the bound is about refusing to scan an unbounded backlog
# inside one HTTP request, not about cost per page. A group holding more than
# this many already-acknowledged events reports what is outstanding rather than
# a false all-clear.
_ACK_MAX_SCAN = 2000


async def _ack_many(
    request: Request,
    alert_ids: list[str],
    *,
    session_id: str,
    caller: str,
) -> tuple[int, int]:
    """Acknowledge ``alert_ids`` concurrently under a bounded semaphore.

    Each id goes through the same ``execute_write_tool`` write path as the
    serial version (identical auth/audit/correctness), but the calls fan out
    via ``asyncio.gather`` capped at ``_ACK_CONCURRENCY`` so a 200-event group
    no longer blocks the HTTP response on hundreds of sequential round-trips.

    Returns ``(acked, failed)``.  A write that returns an error tuple OR raises
    counts as a failure; exceptions never escape (``return_exceptions=True``).
    """
    sem = asyncio.Semaphore(_ACK_CONCURRENCY)

    async def _one(alert_id: str) -> bool:
        async with sem:
            _result, error = await execute_write_tool(
                "ack_alert",
                {"alert_id": alert_id},
                auth=request.app.state.auth,
                settings=request.app.state.settings,
                audit=request.app.state.audit,
                session_id=session_id,
                user=caller,
            )
            return error is None

    results = await asyncio.gather(
        *(_one(alert_id) for alert_id in alert_ids),
        return_exceptions=True,
    )
    acked = 0
    failed = 0
    for r in results:
        if r is True:
            acked += 1
        else:
            # error tuple (r is False) OR a raised exception (BaseException)
            failed += 1
            if isinstance(r, BaseException):
                _LOGGER.warning("bulk-ack write raised (session=%s): %r", session_id, r)
    return acked, failed


# The OQL filter box parses synchronously (lark) on the event loop, and neither
# parse_oql nor validate_oql caps length or clause count — a 30k-term OR body
# (~630 KB) is ~1 s of uninterruptible CPU that the sibling asyncio.timeout
# guards cannot preempt. Cap the field so an oversized body is rejected at
# validation before the parse runs. Mirrors the sibling ``_ES_ID`` annotation.
_OQL_Q = Annotated[str, Field(max_length=2048)]


# The source scopes fetch_group_events can actually select. Anything else used
# to be silently treated as the Suricata/Sigma default — on a WRITE endpoint
# that means acking a different document set than the caller named.
# ``alert`` is the app's OWN fallback kind, not an attacker string: ``_kind_for``
# returns it for any ``tags:alert`` document without a mapped ``event.dataset``,
# ``fetch_groups`` renders it, and the SPA posts the group's kind back verbatim —
# so refusing it 422s Acknowledge/Escalate on a group the analyst can SEE.
# ``fetch_group_events`` treats every non-"notice", non-"unnamed" kind
# identically (the default rule.name-scoped source query), so accepting it is
# not a coercion: the write lands on exactly the document set the group view
# showed.
# ``unnamed`` is the group of alerts carrying no rule.name, named by their
# dataset; refusing it would 422 Acknowledge/Escalate on a group the analyst can
# see, and silently mapping it to the default would resolve a dataset name
# against rule.name and acknowledge nothing while reporting success.
_VALID_GROUP_KINDS = ("suricata", "sigma", "notice", "alert", "unnamed")


class AckGroupIn(BaseModel):
    """Filters for a group-scoped ack/escalate.

    ``kind``/``range``/``severity`` are validated STRICTLY (case-insensitively
    normalized, unrecognized values 422): these filters decide which events a
    write lands on, so a bogus value (e.g. a stale deep-link's
    ``severity=Critical`` before normalization existed) must never be silently
    dropped — that widened the ack to every severity in the group. The read
    endpoints stay lenient; a wrong read shows on screen, a wrong write acks it.
    """

    rule_name: str
    kind: str = "suricata"
    range: str = aq.DEFAULT_RANGE
    q: _OQL_Q | None = None
    severity: str | None = None
    from_: str | None = None
    to: str | None = None

    model_config = {"populate_by_name": True}

    @field_validator("kind")
    @classmethod
    def _validate_kind(cls, v: str) -> str:
        low = v.strip().lower()
        if low not in _VALID_GROUP_KINDS:
            raise ValueError(
                f"unrecognized kind {v!r}; expected one of: {', '.join(_VALID_GROUP_KINDS)}"
            )
        return low

    @field_validator("range")
    @classmethod
    def _validate_range(cls, v: str) -> str:
        low = v.strip().lower()
        if low not in aq.TIME_RANGES:
            raise ValueError(
                f"unrecognized range {v!r}; expected one of: {', '.join(aq.TIME_RANGES)}"
            )
        return low

    @field_validator("severity")
    @classmethod
    def _validate_severity(cls, v: str | None) -> str | None:
        if v is None:
            return None
        low = v.strip().lower()
        if not low:
            return None  # empty ≡ absent — "no severity filter", not a bad value
        # SELECTABLE, not SEVERITIES: "unknown" narrows the write to the alerts
        # that carry no severity label, which the console can now filter to.
        # Rejecting it would leave the analyst looking at a filtered queue they
        # cannot acknowledge, which is the screen disagreeing with its own
        # controls one level along from the badge this batch fixed.
        if low not in aq.SELECTABLE_SEVERITIES:
            raise ValueError(
                f"unrecognized severity {v!r}; "
                f"expected one of: {', '.join(aq.SELECTABLE_SEVERITIES)}"
            )
        return low


async def _count_group(
    elastic: ElasticClient,
    settings: Settings,
    body: AckGroupIn,
) -> int:
    """How many events the group holds, under the filters the write will use."""
    return await aq.count_group_events(
        elastic,
        settings,
        rule_name=body.rule_name,
        kind=body.kind,
        time_range=body.range,
        severity=body.severity,
        oql=body.q,
        abs_from=body.from_,
        abs_to=body.to,
        time_zone=settings.so_timezone,
        hide_acked=True,
    )


def _remaining(matched: int, handled: int, *, more: bool) -> int:
    """Events left in the group after this call handled ``handled`` of them.

    ``more`` is what the paging actually saw and it decides the answer. When the
    scan ran off the end of the group there is nothing left by construction, no
    matter what a count says, so no count is taken at all. When it stopped at
    the cap the count is the only way to put a number on the rest, and the
    answer can never be zero: the scan already proved otherwise.

    ``matched`` is counted under ``hide_acked``, so on a grid that hides an
    acknowledged event it excludes earlier presses and ``handled`` is just this
    call's writes. On a grid that does not, it still counts them and ``handled``
    includes the ones skipped as already done. The subtraction holds either way.
    """
    if not more:
        return 0
    return max(1, matched - handled)


async def _scan_group(
    elastic: ElasticClient,
    settings: Settings,
    body: AckGroupIn,
    *,
    cap: int,
) -> tuple[list[Any], list[Any], bool]:
    """Page a group, splitting it into the events still worth writing to and the
    events Security Onion says it has already handled.

    Returns ``(writable, handled, more)``, capped at ``cap`` writable events.
    ``more`` says at least one further writable event was seen beyond the cap,
    or that the scan hit its bound without reaching the end of the group.

    ``handled`` is returned as the events themselves, not a count, because the
    two flags on them do not mean the same thing to every caller: acknowledged
    is a dismissal and escalated is a case, and only the escalate route has to
    tell them apart.

    The skip cannot be done in the query. ``hide_acked`` filters on
    ``event.acknowledged``, and Elastic Defend's endpoint alert index is mapped
    ``dynamic: false`` without that field, so Security Onion's own ack lands in
    ``_source`` where no query reaches it. Measured on a live SO 3.2.0 grid on
    2026-09-06: a 16-event endpoint group acknowledged cleanly, and the next
    fetch with ``hide_acked=True`` returned the same 16 ids. Reading the flag
    off the hit and paging past it is what makes a second press advance instead
    of rewriting the same events and reporting success.

    What the flags CANNOT tell anyone is whether an alert is on a case. The
    attach soc-ai performs writes a related document on the case and nothing on
    the alert, so an alert this returns as writable may already have a case.
    Deciding that is the escalate route's job, against the ledger and the grid's
    own case links.
    """
    writable: list[Any] = []
    handled: list[Any] = []
    scanned = 0
    offset = 0
    while scanned < _ACK_MAX_SCAN:
        page = await aq.fetch_group_events(
            elastic,
            settings,
            rule_name=body.rule_name,
            kind=body.kind,
            time_range=body.range,
            severity=body.severity,
            oql=body.q,
            size=aq.MAX_EVENTS,
            offset=offset,
            abs_from=body.from_,
            abs_to=body.to,
            time_zone=settings.so_timezone,
            hide_acked=True,
        )
        if not page:
            return writable, handled, False
        scanned += len(page)
        for event in page:
            if event.acknowledged or event.escalated:
                handled.append(event)
            elif len(writable) < cap:
                writable.append(event)
            else:
                return writable, handled, True
        if len(page) < aq.MAX_EVENTS:
            return writable, handled, False
        offset += len(page)
    # Stopped at the scan bound. Whether anything writable is left is unknown,
    # and claiming "nothing" would be the false all-clear this exists to avoid.
    return writable, handled, True


class AckGroupOut(BaseModel):
    acked: int
    failed: int
    total: int
    capped: bool = False
    # Events skipped because Security Onion already records the write. Non-zero
    # only where an acknowledged event stays visible to a query, which is the
    # difference between a button that looks inert and one that explains itself.
    already_acked: int = 0
    # Events in the group this call did not write. Counted against the same
    # filters the write used, so it is the group's own number, not an estimate.
    remaining: int = 0


@router.post("/alerts/ack-group", response_model=AckGroupOut)
async def ack_group(
    request: Request,
    body: AckGroupIn,
    settings: Settings = Depends(get_settings_dep),
    elastic: ElasticClient = Depends(get_elastic),
) -> AckGroupOut:
    """Acknowledge the events of a detection group in Security Onion.

    Collects up to ``_ACK_CAP`` events the grid does not already record as
    acknowledged (see :func:`_scan_group`) and calls ``ack_alert`` for
    each via the write-tool path. Returns how many were acknowledged, how many
    were skipped as already done, and how many are left.

    ``remaining`` is what makes a second press worth making. Before this the
    route acknowledged the same first page every time and reported success every
    time, so a group larger than the cap never emptied and nothing in the answer
    said so.

    The grid read is guarded and bounded like its sibling ``GET /alerts/events``,
    and it runs BEFORE any write: a failed fetch acknowledges nothing, so the
    503 can never arrive on top of a partial ack that a retry would double.
    """
    caller = await identify_caller(request)
    try:
        async with asyncio.timeout(settings.webui_grid_timeout_s):
            events, handled, more = await _scan_group(elastic, settings, body, cap=_ACK_CAP)
            already_acked = len(handled)
            # Only worth a query when the scan stopped short; a drained group
            # already knows its answer. Still a read, and still before the
            # first write, so a grid failure here acknowledges nothing.
            matched = await _count_group(elastic, settings, body) if more else 0
    except OqlValidationError as exc:
        raise HTTPException(
            status_code=400, detail={"reason": "bad_oql", "hint": str(exc)}
        ) from exc
    except (TimeoutError, TransportError) as exc:
        raise HTTPException(status_code=503, detail=_grid_unavailable(exc)) from exc
    except ApiError as exc:
        # An ES ApiError is NOT a TransportError — without this arm an ES 4xx
        # still escapes the tuple above as an unhandled 500.
        raise _es_api_error_http(exc) from exc

    acked = 0
    failed = 0
    if events:
        acked, failed = await _ack_many(
            request,
            [ev.es_id for ev in events],
            session_id=f"ack-group:{body.rule_name}",
            caller=caller,
        )

    remaining = _remaining(matched, already_acked + len(events), more=more)
    if more:
        logging.getLogger(__name__).warning(
            "ack-group capped at %d events for rule %r, %d left (caller=%s)",
            _ACK_CAP,
            body.rule_name,
            remaining,
            caller,
        )

    return AckGroupOut(
        acked=acked,
        failed=failed,
        total=acked + failed,
        capped=more,
        already_acked=already_acked,
        remaining=remaining,
    )


# Escalate is capped far tighter than ack: each escalate opens a SOC case, so a
# group escalate must not spray hundreds of cases. One case per matching event
# mirrors the single-alert escalate_to_case action; the cap bounds the blast.
_ESCALATE_CAP = 25


async def _escalate_many(
    request: Request,
    events: list[Any],
    *,
    rule_name: str,
    session_id: str,
    caller: str,
) -> tuple[int, int, dict[str, str], list[str]]:
    """Escalate ``events`` to Security Onion cases under a bounded semaphore.

    Each event goes through the same ``execute_write_tool`` write path as the
    per-action escalate (identical auth/audit/correctness), fanning out via
    ``asyncio.gather`` capped at ``_ACK_CONCURRENCY``. The escalate tool needs a
    title + description, which the model supplies for the single-alert action;
    here we synthesize a compact, secret-free case title/description from the
    rule name and the event's endpoints.

    Returns ``(escalated, failed, case_ids, empty_cases)``. ``case_ids`` maps
    each alert to the case that was opened for it, so the caller can write the
    answer onto the ledger claim it took out before the write. An alert missing
    from it either failed or came back without an id, and its claim stays open
    rather than being resolved either way.

    A write that created a case and attached nothing to it counts as a failure,
    not an escalate: the alert is on no case. Its case id goes in
    ``empty_cases`` rather than onto the claim, because an empty case with an
    incident's title is now sitting in Security Onion's queue and only the
    operator can close or reuse it.
    """
    sem = asyncio.Semaphore(_ACK_CONCURRENCY)

    # (alert_id, case_id, alert_linked), or None when the write itself failed.
    async def _one(ev: Any) -> tuple[str, str | None, bool] | None:
        async with sem:
            endpoints = f"{ev.src} → {ev.dst}" if getattr(ev, "src", None) else ""
            result, error = await execute_write_tool(
                "escalate_to_case",
                {
                    "alert_id": ev.es_id,
                    "case_title": f"{rule_name}"[:120] or "Escalated alert",
                    "case_description": (
                        f"Escalated from soc-ai: {rule_name}"
                        + (f" ({endpoints})" if endpoints else "")
                    ),
                },
                auth=request.app.state.auth,
                settings=request.app.state.settings,
                audit=request.app.state.audit,
                session_id=session_id,
                user=caller,
            )
            if error is not None:
                return None
            body = result if isinstance(result, dict) else {}
            case_id = body.get("case_id")
            return (
                str(ev.es_id),
                str(case_id) if case_id else None,
                bool(body.get("alert_linked")),
            )

    results = await asyncio.gather(
        *(_one(ev) for ev in events),
        return_exceptions=True,
    )
    escalated = 0
    failed = 0
    case_ids: dict[str, str] = {}
    empty_cases: list[str] = []
    for r in results:
        if isinstance(r, tuple):
            alert_id, case_id, linked = r
            if linked:
                escalated += 1
                if case_id:
                    case_ids[alert_id] = case_id
                continue
            # A case with nothing on it. The claim stays open so the next press
            # can ask the grid and settle it, and the case id is handed back so
            # the operator hears about the case they now have to deal with.
            failed += 1
            if case_id:
                empty_cases.append(case_id)
            _LOGGER.warning(
                "escalate attached nothing for alert %s (case=%s, session=%s)",
                alert_id,
                case_id or "none",
                session_id,
            )
        else:
            failed += 1
            if isinstance(r, BaseException):
                _LOGGER.warning("bulk-escalate write raised (session=%s): %r", session_id, r)
    return escalated, failed, case_ids, empty_cases


class EscalateGroupOut(BaseModel):
    escalated: int
    failed: int
    total: int
    capped: bool = False
    # Alerts a case was WITHHELD from because one already exists for them.
    # soc-ai's own ledger, Security Onion's case links, or the alert's own
    # ``event.escalated`` flag says so. This is the count of duplicate cases not
    # opened, and nothing else belongs in it: it used to also carry every
    # acknowledged alert in the group, which claimed duplicates were prevented
    # where no case had ever existed.
    already_escalated: int = 0
    # Alerts skipped because Security Onion already acknowledged them. A
    # dismissal, not a case, and a different sentence to the operator.
    already_acked: int = 0
    # Alerts an earlier escalate left in an unknown state: it claimed them and
    # never came back with a case id, and the grid could not be asked whether
    # one exists. Neither escalated nor safe to escalate, so they are named
    # rather than folded into a count that would be wrong either way.
    unresolved: int = 0
    # Cases Security Onion created and then attached nothing to, which happens
    # when the alert is no longer on the grid. Each one is an empty case now
    # sitting in the queue under a title that reads like an incident, and each
    # one is counted in ``failed`` rather than ``escalated``: the alert is on no
    # case. Named so the operator can close or reuse them.
    empty_cases: list[str] = []
    remaining: int = 0


async def _existing_case_links(
    elastic: ElasticClient,
    settings: Settings,
    alert_ids: list[str],
) -> dict[str, str] | None:
    """Ask Security Onion which of ``alert_ids`` are already on a case.

    ``None`` means the question could not be answered: a degraded or failing
    read, which is "could not see", never "no case exists". Best-effort by
    design: the ledger is what makes a repeated press safe, and this is the
    wider check that also covers cases opened from Security Onion's own console
    or by another instance. Letting it fail the escalate would trade a
    recoverable gap for an outage.
    """
    if not alert_ids:
        return {}
    try:
        return await case_ids_for_alerts(elastic, settings, alert_ids)
    except Exception:
        _LOGGER.warning("case-link lookup failed; falling back to the ledger", exc_info=True)
        return None


class _Reservation(BaseModel):
    """Which of a press's candidate alerts may actually be escalated."""

    claimed: list[str] = []
    # Alerts a case already exists for: ledger, grid links, or a claim another
    # request took out first.
    already_escalated: int = 0
    # Alerts an earlier escalate claimed and never resolved, that the grid could
    # not be asked about. Left alone rather than escalated or written off.
    unresolved: int = 0


async def _reserve(
    request: Request,
    elastic: ElasticClient,
    settings: Settings,
    candidate_ids: list[str],
    *,
    caller: str,
) -> _Reservation:
    """Reserve the alerts of this press that nothing has a case for yet.

    Three sources answer "is this alert already on a case", in order of how much
    they can be trusted about a press happening right now:

    1. soc-ai's escalation ledger, claimed in the same transaction that reserves
       the alert. It cannot lag and it cannot race, so it is what makes a
       repeated press, or two operators pressing overlapping groups, safe.
    2. Security Onion's case links, which see cases this instance did not open
       but are a refreshed read and so lag by up to a second.
    3. ``event.escalated`` on the alert, handled by the caller before this runs.
    """
    async with request.app.state.db_sessionmaker() as db:
        claims = await esc_svc.cases_for_alerts(db, candidate_ids)
    # Ask the grid only about what the ledger cannot settle: alerts never
    # claimed, and claims whose outcome is still open.
    open_claims = set(esc_svc.unresolved(claims))
    links = await _existing_case_links(
        elastic,
        settings,
        [i for i in candidate_ids if i not in claims or i in open_claims],
    )

    unresolved = 0
    already = 0
    stale: list[str] = []  # claims the grid proves never became a case
    resolved: dict[str, str] = {}  # claims the grid can put a case id on
    to_claim: list[str] = []
    for alert_id in candidate_ids:
        if claims.get(alert_id):
            already += 1  # our own ledger already holds a case for it
        elif alert_id in open_claims:
            if links is None:
                unresolved += 1  # outcome unknown and unknowable right now
            elif alert_id in links:
                resolved[alert_id] = links[alert_id]
                already += 1
            else:
                stale.append(alert_id)  # no case was ever opened; free it
                to_claim.append(alert_id)
        elif links is not None and alert_id in links:
            # A case somebody else opened. Not written to the ledger, which
            # holds soc-ai's own escalations, and the grid answers for it on
            # every press anyway.
            already += 1
        else:
            to_claim.append(alert_id)

    # Claiming is a write, and the session must not stay open across the
    # Security Onion round-trips the caller makes next: a SQLite write lock
    # spanning network calls is how the sweep deadlocked the store.
    async with request.app.state.db_sessionmaker() as db:
        for alert_id, case_id in resolved.items():
            await esc_svc.record_case(db, alert_id, case_id)
        if stale:
            await esc_svc.release(db, stale)
        claimed, already_held = await esc_svc.claim(db, to_claim, actor=caller)
    return _Reservation(
        claimed=claimed,
        already_escalated=already + len(already_held),
        unresolved=unresolved,
    )


@router.post("/alerts/escalate-group", response_model=EscalateGroupOut)
async def escalate_group(
    request: Request,
    body: AckGroupIn,
    settings: Settings = Depends(get_settings_dep),
    elastic: ElasticClient = Depends(get_elastic),
) -> EscalateGroupOut:
    """Escalate a detection group to Security Onion cases.

    Sibling of :func:`ack_group` — same auth/CSRF/signature, the same filters,
    the same :func:`_scan_group` paging. Each matching alert opens a case via
    the ``escalate_to_case`` write tool; ``_ESCALATE_CAP`` bounds the number of
    cases so a group escalate can never spray hundreds.

    Where the ack sibling can decide everything from the alert document, this
    route cannot. Attaching an alert to a case writes a related document on the
    case and nothing on the alert, so the alert's own flags never learn about
    it, and a second press used to open a second case for every alert in the
    group. What may be escalated is decided by :func:`_reserve` against soc-ai's
    own ledger and Security Onion's case links, plus the ``event.escalated``
    flag Security Onion's console stamps when an analyst escalates there.

    Same guarded, bounded, read-before-write shape as :func:`ack_group`: a failed
    fetch opens no cases, so the 503 is never a report on a half-done escalate.
    """
    caller = await identify_caller(request)
    try:
        async with asyncio.timeout(settings.webui_grid_timeout_s):
            events, handled, more = await _scan_group(elastic, settings, body, cap=_ESCALATE_CAP)
            matched = await _count_group(elastic, settings, body) if more else 0
    except OqlValidationError as exc:
        raise HTTPException(
            status_code=400, detail={"reason": "bad_oql", "hint": str(exc)}
        ) from exc
    except (TimeoutError, TransportError) as exc:
        raise HTTPException(status_code=503, detail=_grid_unavailable(exc)) from exc
    except ApiError as exc:
        raise _es_api_error_http(exc) from exc

    # Security Onion's own record of the two skips, kept apart. An escalated
    # alert is on a case; an acknowledged one was dismissed.
    from_flag = sum(1 for ev in handled if ev.escalated)
    already_acked = len(handled) - from_flag

    reserved = await _reserve(
        request, elastic, settings, [ev.es_id for ev in events], caller=caller
    )
    already_escalated = from_flag + reserved.already_escalated
    writable = [ev for ev in events if ev.es_id in set(reserved.claimed)]
    escalated = 0
    failed = 0
    case_ids: dict[str, str] = {}
    empty_cases: list[str] = []
    if writable:
        escalated, failed, case_ids, empty_cases = await _escalate_many(
            request,
            writable,
            rule_name=body.rule_name,
            session_id=f"escalate-group:{body.rule_name}",
            caller=caller,
        )
        async with request.app.state.db_sessionmaker() as db:
            for alert_id, case_id in case_ids.items():
                await esc_svc.record_case(db, alert_id, case_id)

    remaining = _remaining(matched, len(handled) + len(events), more=more)
    if more:
        logging.getLogger(__name__).warning(
            "escalate-group capped at %d events for rule %r, %d left (caller=%s)",
            _ESCALATE_CAP,
            body.rule_name,
            remaining,
            caller,
        )

    return EscalateGroupOut(
        escalated=escalated,
        failed=failed,
        total=escalated + failed,
        capped=more,
        already_escalated=already_escalated,
        already_acked=already_acked,
        unresolved=reserved.unresolved,
        empty_cases=empty_cases,
        remaining=remaining,
    )


_ES_ID = Annotated[str, Field(max_length=512)]  # ES ``_id`` values are <=512 bytes


class AckEventsIn(BaseModel):
    # Cap at the input boundary (mirrors RehuntIn.inv_ids) so an oversized
    # payload is rejected by validation before the dedup/truncate logic below
    # ever parses or iterates it.
    es_ids: list[_ES_ID] = Field(max_length=_ACK_CAP)


@router.post("/alerts/ack-events", response_model=AckGroupOut)
async def ack_events(
    request: Request,
    body: AckEventsIn,
    settings: Settings = Depends(get_settings_dep),
) -> AckGroupOut:
    """Acknowledge a specific set of events by ES id (per-event selection)."""
    caller = await identify_caller(request)
    ids = list(dict.fromkeys(body.es_ids))[:_ACK_CAP]  # dedupe, cap
    capped = len(body.es_ids) > _ACK_CAP
    if not ids:
        return AckGroupOut(acked=0, failed=0, total=0)
    # The ids are caller-supplied — unlike the group routes above, nothing ties
    # them to the alert grid. A promoted hunt finding's anchor is cited
    # telemetry, not an SO alert, and the sibling execute-action route refuses
    # exactly that document with 400 hunt_kind_no_so_target; this route must
    # agree, or the id-supplied path acks what the guarded path refuses.
    # Ordinary alert ids (not hunt anchors) ack normally — that's the job.
    async with request.app.state.db_sessionmaker() as db:
        hunt_anchors = await inv_svc.hunt_anchor_ids(db, ids)
    if hunt_anchors:
        raise HTTPException(
            status_code=400,
            detail={
                "reason": "hunt_kind_no_so_target",
                "ids": sorted(hunt_anchors),
                "hint": "A promoted finding has no Security Onion alert to act on.",
            },
        )
    acked, failed = await _ack_many(
        request,
        ids,
        session_id="ack-events",
        caller=caller,
    )

    if capped:
        logging.getLogger(__name__).warning(
            "ack-events capped at %d events (caller=%s)",
            _ACK_CAP,
            caller,
        )

    return AckGroupOut(acked=acked, failed=failed, total=acked + failed, capped=capped)


# ── Alert assignment ───────────────────────────────────────────────────────


class AssignIn(BaseModel):
    rule_name: str
    unassign: bool = False
    # Optional triage-state transition (E2.3). When omitted on an assign the state
    # defaults to "owned"; passing e.g. "in_review"/"done" moves an ALREADY-owned
    # rule through the triage flow without changing the owner. Ignored on unassign
    # (clearing the row drops the state with it).
    state: str | None = None


class AssignOut(BaseModel):
    rule_name: str
    owner: str | None
    state: str | None = None


async def _audit_assignment(
    request: Request,
    *,
    rule_name: str,
    action: str,
    owner: str | None,
    state: str | None,
) -> None:
    """Best-effort audit of an assignment change (assign / state / unassign).

    Mirrors E1.1's model_fitness audit: a failed audit index must never turn a
    successful assignment into a 500, so the whole thing is wrapped and logged,
    never raised. ``action`` is one of ``assign`` | ``state`` | ``unassign``.
    """
    try:
        caller = await identify_caller(request)
        audit = getattr(request.app.state, "audit", None)
        if audit is not None:
            await audit.log_kind(
                session_id=f"assignment:{rule_name}",
                kind="assignment",
                payload={
                    "rule_name": rule_name,
                    "action": action,
                    "owner": owner,
                    "state": state,
                },
                user=caller,
            )
    except Exception:  # audit is best-effort — an assignment must never 500 on it
        _LOGGER.warning("assignment audit write failed (continuing)", exc_info=True)


@router.post("/alerts/assign", response_model=AssignOut)
async def assign_alert(
    request: Request,
    body: AssignIn,
) -> AssignOut:
    """Persist (or clear) the owner + triage state for a detection rule.

    Three shapes, all through the one endpoint (an analyst action — same auth as
    the surrounding ack/escalate routes, not admin-only):

    * ``unassign=True`` — remove the row (owner + state gone; back to the
      "unassigned" no-row state).
    * ``state`` set (no unassign) — move an EXISTING assignment through the
      triage flow (``owned`` → ``in_review`` → ``done``) without changing owner.
      A 404 if the rule has no owner (state requires an owner).
    * otherwise — assign the caller as owner (resetting state to ``owned``). The
      owner value is a plain username when authenticated via session,
      ``token:<name>`` for a bearer token, or ``"anonymous"`` when auth is off.

    Every change is audited best-effort (``assignment`` kind).
    """
    async with request.app.state.db_sessionmaker() as db:
        if body.unassign:
            await assign_svc.clear_assignment(db, body.rule_name)
            await _audit_assignment(
                request, rule_name=body.rule_name, action="unassign", owner=None, state=None
            )
            return AssignOut(rule_name=body.rule_name, owner=None, state=None)

        # State-only transition on an existing assignment (owner unchanged).
        if body.state is not None:
            try:
                applied = await assign_svc.set_state(db, body.rule_name, body.state)
            except ValueError as exc:
                raise HTTPException(
                    status_code=400, detail={"reason": "bad_state", "hint": str(exc)}
                ) from exc
            if not applied:
                raise HTTPException(
                    status_code=404,
                    detail={
                        "reason": "not_assigned",
                        "hint": "assign an owner before setting a triage state",
                    },
                )
            record = await assign_svc.assignments_for_rules(db, [body.rule_name])
            rec = record.get(body.rule_name, {})
            await _audit_assignment(
                request,
                rule_name=body.rule_name,
                action="state",
                owner=rec.get("owner"),
                state=body.state,
            )
            return AssignOut(rule_name=body.rule_name, owner=rec.get("owner"), state=body.state)

        # Plain assign: caller becomes owner, state resets to "owned".
        owner = await identify_caller(request)
        await assign_svc.set_assignment(db, body.rule_name, owner)
    await _audit_assignment(
        request, rule_name=body.rule_name, action="assign", owner=owner, state="owned"
    )
    return AssignOut(rule_name=body.rule_name, owner=owner, state="owned")


class StrandedClaimOut(BaseModel):
    """One escalate whose outcome nobody ever learned.

    The ledger claims an alert BEFORE opening the case, so the row exists for
    the moment between the claim and the answer. A row that never got its
    answer means the request either created a case and failed on the attach, or
    failed before Security Onion wrote anything — and this deployment cannot
    tell which, which is the whole point of not guessing.
    """

    alert_id: str
    # ``identify_caller`` output: a username, ``token:<name>``, or "anonymous".
    escalated_by: str
    # When the claim was taken, ISO-8601 with a Z. The age is the fact that
    # matters: a claim from four minutes ago is a request in flight, and one
    # from four days ago is an alert nobody can escalate.
    claimed_at: str


class StrandedClaimsOut(BaseModel):
    """What the ledger is holding that nothing will settle on its own.

    ``total`` is a COUNT over the whole matching set, not ``len(claims)``. The
    list is capped, and a surface that showed fifty rows and called it fifty
    would under-report a ledger holding two hundred — the same silent
    truncation this page exists to end.

    ``settling_minutes`` rides along because zero claims mean different things
    with different windows, and because the number is what makes the list
    defensible: without it, "nothing stranded" could be read as a claim-first
    ledger that simply has not been looked at quickly enough.
    """

    claims: list[StrandedClaimOut]
    total: int
    settling_minutes: int


@router.get("/escalations/stranded", response_model=StrandedClaimsOut)
async def list_stranded_escalations(request: Request) -> StrandedClaimsOut:
    """Escalate claims that never came back with a case id.

    Reads soc-ai's own ledger and nothing else — no grid call, so this answers
    on a deployment whose case index is unreadable, which is exactly the
    deployment that accumulates these.

    Analyst-readable rather than admin-gated, on the same argument as the hunt
    catalog: it names alerts the analyst already sees and the account that
    pressed escalate, and the person who needs to know an alert cannot be
    escalated is the person trying to escalate it.

    Reconciliation stays where it is — the next group escalate covering the
    alert settles the claim against the grid's own case links. This route is
    the surface, not a second write path: an operator-facing "release" button
    would drop a claim on somebody's opinion rather than on evidence, and a
    request can fail after Security Onion has already created the case.
    """
    now = datetime.now(UTC).replace(tzinfo=None)
    async with request.app.state.db_sessionmaker() as db:
        rows, total = await esc_svc.stranded(db, now=now)
    return StrandedClaimsOut(
        claims=[
            StrandedClaimOut(
                alert_id=row.alert_id,
                escalated_by=row.escalated_by,
                # Never None: the column is NOT NULL with a server default.
                claimed_at=_iso_z(row.created_at) or "",
            )
            for row in rows
        ],
        total=total,
        settling_minutes=int(esc_svc.SETTLING.total_seconds() // 60),
    )
