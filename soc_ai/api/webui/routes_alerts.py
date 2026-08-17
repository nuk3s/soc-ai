"""Alert list / group events / representative-event endpoints."""

from __future__ import annotations

import asyncio
import logging
import re
from collections import Counter

from elastic_transport import TransportError
from elasticsearch import ApiError
from fastapi import Depends, HTTPException, Query, Request
from pydantic import BaseModel

from soc_ai.api.deps import get_elastic, get_settings_dep
from soc_ai.api.webui._shared import (
    _ago,
    _inv_ago,
    _kind,
    _sev,
    _verdict,
    router,
)
from soc_ai.config import Settings
from soc_ai.errors import OqlValidationError
from soc_ai.so_client.elastic import ElasticClient, GridPartialResultsError
from soc_ai.store import assignments as assign_svc
from soc_ai.store import detection_overrides as override_svc
from soc_ai.store import investigations as inv_svc
from soc_ai.store.models import Investigation
from soc_ai.triage_models import is_pipeline_fallback
from soc_ai.webui import alerts_query as aq

_LOGGER = logging.getLogger(__name__)

# Cap the OQL filter query param: it parses synchronously (lark) on the event
# loop with no length/clause limit, so an oversized ``q`` is ~1 s of
# uninterruptible CPU. Reject it at validation (422) before the parse runs —
# the query-param mirror of ``AckGroupIn``'s ``_OQL_Q`` body cap.
_OQL_Q_MAXLEN = 2048

# The default 503 body: the grid never answered, because the connection was
# refused or the read ran out of time. "Retry shortly" is real advice there —
# the next attempt genuinely may succeed — and it must stay on those classes.
_GRID_UNAVAILABLE = {
    "reason": "grid_unavailable",
    "hint": ("The Security Onion grid (Elasticsearch) is slow or unreachable — retry shortly."),
}

# An Elasticsearch exception TYPE token, e.g. ``circuit_breaking_exception``.
_ES_FAILURE_TYPE_RE = re.compile(r"[a-z][a-z0-9_]{0,63}")


def _es_failure_type(reason: str | None) -> str | None:
    """The ES exception type from a shard-failure reason, or ``None``.

    Deliberately not the whole reason string. A shard failure reason carries
    node names and ``host:port`` pairs, and an operator-facing hint is the wrong
    place for grid internals — the type alone is the actionable half, and the
    pattern keeps everything else out by construction rather than by scrubbing.
    """
    if not reason:
        return None
    head = reason.split(":", 1)[0].strip()
    return head if _ES_FAILURE_TYPE_RE.fullmatch(head) else None


def _partial_read_hint(exc: GridPartialResultsError) -> str:
    """What to tell the operator when the grid answered from only some shards.

    A partial read is not slowness and not unreachability: the grid answered
    200, fast, off part of the index. Both halves of the default hint are wrong
    for it, and the second half is actively harmful — "retry shortly" sends the
    analyst around a loop that returns the same short answer every time, because
    nothing about the next request changes shard health. Say which shards were
    missed (the count the exception already carries), say the result is
    incomplete rather than empty, and point at the one system that can fix it.
    """
    parts: list[str] = []
    if exc.shards_failed:
        if exc.shards_total:
            read = max(exc.shards_total - exc.shards_failed, 0)
            parts.append(f"read only {read} of {exc.shards_total} shards")
        else:
            noun = "shard" if exc.shards_failed == 1 else "shards"
            parts.append(f"could not read {exc.shards_failed} {noun}")
    if exc.timed_out:
        parts.append("ran out of time before every shard answered")
    if not parts:
        # Defensive: a partial read with neither counter set still gets a
        # partial read's advice, never the unreachable-grid advice.
        parts.append("did not read every shard")
    cause = _es_failure_type(exc.reason)
    detail = f" (first shard failure: {cause})" if cause else ""
    return (
        f"The Security Onion grid answered, but the search {' and '.join(parts)}{detail}. "
        "These results are incomplete, not empty — a short or missing answer here means "
        "unknown. Repeating the search returns the same partial read until Elasticsearch "
        "shard health recovers; check the cluster's shard allocation."
    )


def _grid_unavailable(exc: BaseException | None = None) -> dict[str, str]:
    """The 503 body for a grid failure, with the hint chosen by failure CLASS.

    One hint for every way a grid can fail is one hint too few. A refused
    connection and a half-read index are different outages with different
    remedies, and the flat constant described the second as the first — "slow or
    unreachable" for a grid that answered in under 100 ms, followed by the only
    advice on screen being an action that cannot work.

    ``GridPartialResultsError`` gets the shard story; everything else keeps
    :data:`_GRID_UNAVAILABLE` unchanged, because "retry shortly" is true of a
    connect failure and a read timeout and pointing those at shard health would
    send the analyst to the wrong system.
    """
    if isinstance(exc, GridPartialResultsError):
        return {"reason": "grid_unavailable", "hint": _partial_read_hint(exc)}
    return _GRID_UNAVAILABLE


def _es_api_error_http(exc: ApiError) -> HTTPException:
    """Map an ``elasticsearch.ApiError`` to a clean HTTP error.

    A ``BadRequestError`` (and its ApiError siblings) is NOT a ``TransportError``,
    so it slips past the ``(TimeoutError, TransportError)`` tuple and used to
    surface as an unhandled 500. A 4xx from ES is a bad query → 400; anything
    else (a 5xx the transport did not already retry) is a grid problem → 503.

    429 is the exception to that split, and it is not a corner case: it is what a
    saturated grid answers — search queue full, or an aggregation tripping the
    parent circuit breaker. Nothing is wrong with the query, the cluster is over
    its limits, and the same request succeeds once it recovers. Sorting it by HTTP
    number put it in the bad-query bucket and told the analyst to check fields and
    a time range they may never have typed (the dossier activity panel and the
    detection-tuning panel take no query at all), while hiding the one fact that
    matters: this is retryable. It is the grid's story, so it gets the grid's
    answer — a 503 the SPA already renders as a retryable card.

    408 joins it for the same reason, and more plainly still: a request-timeout
    status is a statement about the GRID, never about the query text. Nothing an
    analyst can type makes a search finish inside a proxy's patience, and RFC
    9110 says outright that the client may repeat the request — the definition of
    retryable. In practice a 408 in front of Elasticsearch is a load balancer
    giving up under load, and filing it as a bad query told the analyst to check
    the fields and time range of a filter they never typed. Three classifiers
    answer this question (here, ``webui.autotriage._is_query_class`` and
    ``agent.toolset._is_grid_unavailable``); the toolset had 408 right first.
    """
    status = getattr(getattr(exc, "meta", None), "status", None)
    if status is not None and 400 <= status < 500 and status not in (408, 429):
        return HTTPException(
            status_code=400,
            detail={
                "reason": "bad_query",
                "hint": "Elasticsearch rejected the query — check the fields and time range.",
            },
        )
    return HTTPException(status_code=503, detail=_GRID_UNAVAILABLE)


class AlertEventOut(BaseModel):
    id: str = ""  # es _id — needed by the upcoming per-event selection feature
    src: str
    dst: str
    host: str
    # Address of the machine the detection fired ON, when it is an endpoint agent
    # rather than a flow. Separate from src/dst on purpose: those are FLOW
    # endpoints, and a host detection has none. None for flow-shaped alerts.
    hostIp: str | None = None
    proto: str = ""
    sev: str = "low"  # normalized severity label
    port: int | None = None  # destination port
    ts: str = ""  # raw ISO @timestamp (for sorting / tooltip)
    ago: str = ""  # short relative label ("3m")
    investigated: bool = False  # True when this exact event was investigated
    invId: str | None = None  # investigation whose verdict applies to this event
    inheritedReason: str | None = None  # human-readable reason when verdict is inherited
    # Relative time of the investigation that gave this event its verdict, for BOTH
    # the direct-investigated and inherited cases ("8m" → "investigated 8m ago").
    # The inheritedReason string also embeds it, but a structured field lets the row
    # render the investigation's time next to the alert's own time without regex.
    investigatedAt: str | None = None


class LastAttemptOut(BaseModel):
    """A FAILED retry stacked on top of a standing verdict (E2.1).

    Present only when the NEWEST run for a rule is terminal-non-complete
    (error/cancelled/interrupted) OR a pipeline fallback, AND an older, genuine
    (non-fallback) complete verdict is still standing. It answers the "stayed at
    Needs Info" mystery: the row keeps its real verdict, but this note surfaces
    that the last re-run crashed. ``status`` ∈ {error, cancelled, interrupted,
    fallback}; ``ago`` is a short relative label ("5m")."""

    status: str
    ago: str


class AlertGroupOut(BaseModel):
    id: str
    name: str
    kind: str
    sev: str
    count: int
    verdict: str
    conf: float | None = None
    latest: str
    latestTs: str = ""
    inherited: bool = False
    owner: str | None = None
    # Human triage state on the assignment (E2.3): "owned" | "in_review" | "done".
    # None when the rule is unassigned (no assignment row) — the "unassigned"
    # state is the absence of an owner, so state is only meaningful with an owner.
    state: str | None = None
    # Representative flow (source → destination) from the group's latest event, so
    # the collapsed row shows BOTH hosts at a glance instead of hiding them.
    src: str | None = None
    dst: str | None = None
    events: list[AlertEventOut] = []
    # The investigation whose verdict this badge shows — the drawer opens it
    # directly (None when the rule has never been investigated).
    invId: str | None = None
    # When inherited, why (so the analyst knows it wasn't investigated directly).
    inheritedReason: str | None = None
    # True when the rule's latest investigation is still running — the badge
    # will show "Triaging…" instead of "untriaged".
    triaging: bool = False
    # Count of acknowledged / escalated events in this group (from ES aggs).
    ackedCount: int = 0
    escalatedCount: int = 0
    # True when an operator has muted this rule (detection tuning). Muted groups
    # are EXCLUDED from the default feed; they appear (flagged) only with
    # ?include_muted=true.
    muted: bool = False
    # True when the rule's STANDING verdict is a pipeline-failure fallback (E1.2)
    # — a needs_more_info the pipeline never reasoned to (model truncation,
    # gateway 5xx). The Alerts row renders a distinct "pipeline error — retry"
    # chip, and the Dashboard excludes such groups from the Needs-info KPI.
    fallback: bool = False
    # A FAILED retry stacked on top of the STANDING verdict (E2.1): the newest run
    # for this rule crashed (error/cancelled/interrupted) or fell back, while an
    # older genuine verdict still stands. None when the newest run IS the standing
    # verdict (no failed retry) — surfaces the "stayed at Needs Info" mystery.
    lastAttempt: LastAttemptOut | None = None


# Terminal statuses that mean a run FAILED without landing a verdict — the
# re-huntable set (mirrors :func:`inv_svc.blocks_rehunt`'s complement, minus
# "running" which is an in-flight retry surfaced by `triaging`, not a failure).
_FAILED_STATUSES = frozenset({"error", "cancelled", "interrupted"})


def _last_attempt(
    newest: Investigation | None, standing: Investigation | None
) -> LastAttemptOut | None:
    """The failed-retry note for a rule, or None (E2.1).

    ``newest`` is the rule's most-recent run of ANY status (``latest_for_rules``);
    ``standing`` is its latest COMPLETE verdict (``latest_complete_for_rules``).
    A failed retry is surfaced only when a GENUINE verdict is standing AND a LATER
    attempt failed — so the standing verdict chip stays primary and this is a
    secondary hint. Concretely:

    * ``standing`` must exist and NOT itself be a pipeline fallback — if the
      standing verdict is the fallback, E1.2's pipeline-error chip already owns the
      failure signal (and there is no genuine verdict to stack a failed retry on).
    * ``newest`` must be a DIFFERENT, LATER run than ``standing`` (a failed retry
      on top of it) — if the newest run IS the standing complete verdict, there is
      no failure to show.
    * ``newest`` must be terminal-non-complete (error/cancelled/interrupted) OR a
      pipeline fallback (a fallback is a ``complete`` row, so status alone misses
      it — see E1.2).

    No extra query: both inputs are already fetched by :func:`list_alerts`.
    """
    if newest is None or standing is None:
        return None
    # A fallback standing verdict is E1.2's job, not E2.1's.
    if is_pipeline_fallback(getattr(standing, "report", None)):
        return None
    # The newest run IS the standing verdict → no failed retry on top of it.
    if newest.id == standing.id:
        return None
    fell_back = is_pipeline_fallback(getattr(newest, "report", None))
    if newest.status not in _FAILED_STATUSES and not fell_back:
        return None
    status = "fallback" if fell_back else newest.status
    ago = _inv_ago(newest) or "?"
    return LastAttemptOut(status=status, ago=ago)


def _inherited_reason(inv: Investigation) -> str:
    """Human explanation for an inherited verdict — WHICH investigation and WHEN,
    so the analyst can trust (and open) the source rather than seeing an opaque
    'inherited' badge.

    The flow is named only when the source run HAS one. A host/process detection
    observes no network flow at all, and rendering its verdict as "on ? → ?" made
    a perfectly good inherited verdict read like missing data.
    """
    when = _ago(inv.created_at.isoformat()) if inv.created_at else "?"
    flow = f" on {inv.src_ip or '?'} → {inv.dest_ip or '?'}" if (inv.src_ip or inv.dest_ip) else ""
    return (
        f"Inherited — same detection, investigated {when} ago{flow} (investigation {inv.id[:8]}…)"
    )


@router.get("/alerts", response_model=list[AlertGroupOut])
async def list_alerts(
    request: Request,
    range_: str = Query("24h", alias="range"),
    severity: str | None = None,
    q: str | None = Query(None, max_length=_OQL_Q_MAXLEN),
    sort: str = "count",
    from_: str | None = Query(None, alias="from"),
    to: str | None = None,
    hide_acked: bool = Query(False),
    include_muted: bool = Query(False),
    settings: Settings = Depends(get_settings_dep),
    elastic: ElasticClient = Depends(get_elastic),
) -> list[AlertGroupOut]:
    """Grouped-by-detection rows for the Alerts console (events loaded lazily).

    Rules an operator has muted (detection tuning) are EXCLUDED from the default
    feed; pass ``include_muted=true`` to show them (each flagged ``muted: true``).
    """
    try:
        async with asyncio.timeout(settings.webui_grid_timeout_s):
            groups, _total = await aq.fetch_groups(
                elastic,
                settings,
                time_range=range_,
                severity=severity,
                oql=q,
                sort=sort,
                abs_from=from_,
                abs_to=to,
                time_zone=settings.so_timezone,
                hide_acked=hide_acked,
            )
    except OqlValidationError as exc:
        raise HTTPException(
            status_code=400, detail={"reason": "bad_oql", "hint": str(exc)}
        ) from exc
    except (TimeoutError, TransportError) as exc:
        # Fail fast with a clean error instead of hanging the console while the
        # ES client retries a slow/unreachable Security Onion grid.
        raise HTTPException(status_code=503, detail=_grid_unavailable(exc)) from exc
    except ApiError as exc:
        # An ES ApiError (e.g. BadRequestError) is NOT a TransportError — map it
        # here so a bad query is a 400, not an unhandled 500.
        raise _es_api_error_http(exc) from exc

    # Verdict badge per rule = the rule's STANDING verdict (its latest COMPLETE,
    # verdict-bearing investigation). A later interrupted run (error/cancelled/
    # still-running) must NOT erase that verdict — it only drives the separate
    # "Triaging…" flag. This keeps the group badge consistent with the per-event
    # labels (which already match on complete investigations). "inherited" = the
    # verdict came from a different alert than this group's latest event.
    # badge per rule: (verdict, conf, cross_alert_inherited, inv_id, investigated_pair)
    badges: dict[str, tuple[str, float | None, bool, str, str]] = {}
    assignments: dict[str, dict[str, str]] = {}
    verdicts: dict[str, Investigation] = {}
    # Newest run of ANY status per rule — drives the "Triaging…" flag AND the E2.1
    # failed-retry note. Already fetched below; hoisted here so the render loop can
    # read it without a re-fetch (no N+1).
    latest_any: dict[str, Investigation] = {}
    running_rules: set[str] = set()
    muted_rules: set[str] = set()
    if groups:
        rule_names = [g.rule_name for g in groups]
        async with request.app.state.db_sessionmaker() as db:
            verdicts = await inv_svc.latest_complete_for_rules(db, rule_names)
            latest_any = await inv_svc.latest_for_rules(db, rule_names)
            assignments = await assign_svc.assignments_for_rules(db, rule_names)
            muted_rules = await override_svc.muted_rule_names(db)
        # The id of the in-flight run per rule, so a "Triaging…" row links straight
        # to its live investigation (a running row has no completed verdict, so its
        # id never lands in `badges`/`verdicts`) — fixes the "only a Hunt link" gap.
        running_inv_ids = {r: inv.id for r, inv in latest_any.items() if inv.status == "running"}
        running_rules = set(running_inv_ids)
        latest_ids = {g.rule_name: g.latest_id for g in groups}
        for rule, inv in verdicts.items():
            inherited = inv.alert_es_id != latest_ids.get(rule)
            pair = f"{inv.src_ip or '?'} → {inv.dest_ip or '?'}"
            badges[rule] = (_verdict(inv.verdict), inv.confidence, inherited, inv.id, pair)

    out: list[AlertGroupOut] = []
    for g in groups:
        is_muted = g.rule_name in muted_rules
        # Detection tuning: a muted rule is hidden from the default feed (a soft,
        # soc-ai-side suppression — SO is untouched). It only surfaces, flagged,
        # when the caller explicitly asks to include muted rules.
        if is_muted and not include_muted:
            continue
        verdict, conf, inherited, inv_id, pair = badges.get(
            g.rule_name, ("untriaged", None, False, "", "")
        )
        is_running = g.rule_name in running_rules
        # A verdict is reached by investigating ONE representative alert and then
        # applied to the whole group — so the other events inherit it. Surface
        # that coverage (the analyst should know it's a sampled verdict), and
        # flag the stronger case where even the representative differs.
        reason: str | None = None
        _inv = verdicts.get(g.rule_name)
        # The badge is a pipeline fallback when the rule's STANDING verdict run
        # carries the marker (E1.2). `latest_complete_for_rules` loads the full
        # ORM row, so `.report` (the JSON column) is available.
        is_fallback = _inv is not None and is_pipeline_fallback(getattr(_inv, "report", None))
        # E2.1: a failed RETRY stacked on the standing verdict. The newest run of
        # any status (`latest_any`) is the "last attempt"; it's a failure only when
        # it's newer than the genuine standing verdict AND terminal-non-complete or
        # a fallback. Reuses data already in hand — no per-rule query.
        last_attempt = _last_attempt(latest_any.get(g.rule_name), _inv)
        if inv_id and inherited and _inv is not None:
            reason = _inherited_reason(_inv)
        elif inv_id and g.count > 1:
            reason = f"Verdict from 1 of {g.count} events investigated"
        out.append(
            AlertGroupOut(
                id=g.latest_id or g.rule_name,
                name=g.rule_name,
                kind=_kind(g.kind),
                sev=_sev(g.severity),
                count=g.count,
                verdict=verdict,
                conf=conf,
                latest=_ago(g.latest_ts),
                latestTs=g.latest_ts or "",
                inherited=inherited,
                owner=(assignments.get(g.rule_name) or {}).get("owner"),
                state=(assignments.get(g.rule_name) or {}).get("state"),
                src=g.src_ip,
                dst=g.dst_ip,
                events=[],
                # Completed verdict's investigation if there is one, else the
                # in-flight run's id so a "Triaging…" row opens its live drawer.
                invId=inv_id or running_inv_ids.get(g.rule_name) or None,
                inheritedReason=reason,
                # "Triaging…" means this group has a LIVE investigation right now —
                # keyed off the DB (latest run status == "running"), not the sweep's
                # queue. The worker is sequential, so exactly the in-flight group
                # shows it; the pill clears the instant that run finishes, and the
                # triaging count matches the running-investigations count. Queued
                # groups stay "untriaged" (their true state) until their turn.
                triaging=is_running,
                ackedCount=g.acked_count,
                escalatedCount=g.escalated_count,
                muted=is_muted,
                fallback=is_fallback,
                lastAttempt=last_attempt,
            )
        )
    return out


@router.get("/alerts/events", response_model=list[AlertEventOut])
async def list_group_events(
    request: Request,
    rule_name: str,
    kind: str = "suricata",
    range_: str = Query("24h", alias="range"),
    severity: str | None = None,
    q: str | None = Query(None, max_length=_OQL_Q_MAXLEN),
    hide_acked: bool = Query(False),
    size: int = Query(aq.EVENTS_PER_GROUP, ge=1, le=aq.MAX_EVENTS),
    offset: int = Query(0, ge=0),
    from_: str | None = Query(None, alias="from"),
    to: str | None = None,
    settings: Settings = Depends(get_settings_dep),
    elastic: ElasticClient = Depends(get_elastic),
) -> list[AlertEventOut]:
    """Flat events for one detection group, newest first (the row-expand view).

    Paginate large groups with ``size`` + ``offset`` ("load more")."""
    try:
        async with asyncio.timeout(settings.webui_grid_timeout_s):
            events = await aq.fetch_group_events(
                elastic,
                settings,
                rule_name=rule_name,
                kind=kind,
                time_range=range_,
                severity=severity,
                oql=q,
                size=size,
                offset=offset,
                hide_acked=hide_acked,
                abs_from=from_,
                abs_to=to,
                time_zone=settings.so_timezone,
            )
    except OqlValidationError as exc:
        raise HTTPException(
            status_code=400, detail={"reason": "bad_oql", "hint": str(exc)}
        ) from exc
    except (TimeoutError, TransportError) as exc:
        raise HTTPException(status_code=503, detail=_grid_unavailable(exc)) from exc
    except ApiError as exc:
        raise _es_api_error_http(exc) from exc

    # Three batched DB lookups — no per-event queries (no N+1).
    # 1. Direct: events whose exact es_id was investigated.
    # 2. Pair: events matching a (rule, src_ip, dst_ip) from a complete investigation.
    # 3. Rule: any complete investigation for this rule (rule-level fallback).
    async with request.app.state.db_sessionmaker() as db:
        direct = await inv_svc.latest_for_alerts(db, [e.es_id for e in events])
        # A missing endpoint DEGRADES to "" rather than dropping the event from the
        # pair tier — the same coalescing the sweep planner's clustering uses, and
        # the shape the store's pair helpers already key on. Filtering to
        # both-endpoints-present meant a host/process detection could never match
        # its own cluster's verdict and fell through to the rule-level standing
        # verdict, which on a rule that ALSO fires on flows credited the host
        # detection to an unrelated flow.
        pairs: list[tuple[str, str, str]] = [
            (rule_name, e.src_ip or "", e.dst_ip or "") for e in events
        ]
        pair_map = await inv_svc.latest_for_pairs(
            db, pairs, window_days=settings.webui_inherit_window_days
        )
        # Rule-level fallback uses the rule's STANDING verdict (latest complete,
        # verdict-bearing) — same source as the group badge — so every event in a
        # triaged group inherits consistently. (Using the most-recent run of ANY
        # status would skip the fallback whenever a later run errored/was
        # cancelled, leaving some events mislabelled "untriaged".)
        # Per-alert inheritance fallback: bound by the SAME window as the pair
        # tier so a rule's stale standing verdict isn't inherited onto fresh
        # alerts (the "inherited a verdict from 18d ago, past my window" bug).
        # The rule-GROUP standing badge deliberately stays unbounded.
        rule_map = await inv_svc.latest_complete_for_rules(
            db, [rule_name], window_days=settings.webui_inherit_window_days
        )
    rule_inv = rule_map.get(rule_name)

    out: list[AlertEventOut] = []
    for e in events:
        base = AlertEventOut(
            id=e.es_id,
            src=e.src,
            dst=e.dst,
            host=e.host,
            hostIp=e.host_ip,
            sev=_sev(e.severity),
            port=e.dst_port,
            ts=e.timestamp,
            ago=_ago(e.timestamp),
        )
        direct_inv = direct.get(e.es_id)
        pair_inv = pair_map.get((rule_name, e.src_ip or "", e.dst_ip or ""))
        # A DIRECT run of this exact alert only "owns" it (investigated, NOT
        # inherited) when it is complete (a landed verdict) or still running (an
        # in-flight re-run). An error/cancelled direct run produced no verdict, so
        # it must NOT claim the alert — fall through to the inherited pair/rule
        # verdict (same re-huntable treatment as blocks_rehunt). This is the fix
        # for "re-ran ON this alert but the pill still says inherited": the fresh
        # re-run's alert_es_id == this event's es_id, so it lands here and clears
        # the inherited flag.
        if direct_inv is not None and direct_inv.status in ("complete", "running"):
            base.investigated = True
            base.invId = direct_inv.id
            base.inheritedReason = None
            base.investigatedAt = _inv_ago(direct_inv)
        elif pair_inv is not None:
            base.investigated = False
            base.invId = pair_inv.id
            base.inheritedReason = _inherited_reason(pair_inv)
            base.investigatedAt = _inv_ago(pair_inv)
        elif rule_inv is not None:  # already complete + verdict-bearing
            base.investigated = False
            base.invId = rule_inv.id
            base.inheritedReason = _inherited_reason(rule_inv)
            base.investigatedAt = _inv_ago(rule_inv)
        out.append(base)
    return out


# ── Representative-event picker ────────────────────────────────────────────


class RepresentativeOut(BaseModel):
    alert_id: str
    src_ip: str | None = None
    dst_ip: str | None = None
    dst_port: int | None = None
    matched: int
    total: int
    reason: str


# The shape an event is clustered by when picking a representative: a missing
# endpoint coalesces to "" so no-flow events form their own legitimate shape
# instead of being excluded from the count.
_FlowKey = tuple[str, str, int | None]


def _flow_key(event: aq.AlertEvent) -> _FlowKey:
    return (event.src_ip or "", event.dst_ip or "", event.dst_port)


def _pick_representative(
    events: list[aq.AlertEvent],
) -> tuple[aq.AlertEvent, int, str]:
    """Return (event, matched_count, reason) for the most-representative event.

    Selection rule:
    1. Count occurrences of each (src_ip, dst_ip, dst_port) shape across ALL
       events, coalescing a missing endpoint to "" (see :func:`_flow_key`).
    2. Modal shape wins; ties broken by the most-recent event in that shape.
    3. Within the winning shape choose the *newest* event.

    Counting only both-endpoints-present events is what this used to do, and on a
    host/process detection — which carries no source/destination at all — it meant
    a single stray flow-bearing event could be elected "most representative" of a
    cluster it was a 1-in-N outlier of, sending the operator's hunt at the outlier.
    A group with no flow anywhere degenerates to one shape, so the representative
    is simply its newest event (what the old no-IP fallback did) — but ``matched``
    now reports the whole shape instead of a hardcoded 1.
    """
    counts: Counter[_FlowKey] = Counter(_flow_key(e) for e in events)
    # Find the maximum count, then among all shapes with that count pick the one
    # whose most-recent event is latest (tie-break by recency of the shape).
    max_count = max(counts.values())
    winning_keys = [t for t, c in counts.items() if c == max_count]

    def _key_newest_ts(key: _FlowKey) -> str:
        return max((e.timestamp for e in events if _flow_key(e) == key), default="")

    winning_key = max(winning_keys, key=_key_newest_ts)
    src_ip, dst_ip, dst_port = winning_key

    # Pick the newest event within the winning shape.
    candidates = [e for e in events if _flow_key(e) == winning_key]
    representative = max(candidates, key=lambda e: e.timestamp)

    if not src_ip and not dst_ip:
        # Never render "— → —": these events observed no flow, they didn't lose one.
        shape = "No network flow on these events (host-shaped detection)"
    else:
        dst_label = f"{dst_ip or '—'}:{dst_port}" if dst_port is not None else (dst_ip or "—")
        shape = f"Most common flow {src_ip or '—'} → {dst_label}"
    reason = (
        f"{shape} — {max_count} of {len(events)} events;"
        f" representative = newest ({representative.timestamp})."
    )
    return representative, max_count, reason


@router.get("/alerts/representative", response_model=RepresentativeOut)
async def get_representative(
    rule_name: str,
    kind: str = "suricata",
    range_: str = Query(aq.DEFAULT_RANGE, alias="range"),
    severity: str | None = None,
    q: str | None = Query(None, max_length=_OQL_Q_MAXLEN),
    hide_acked: bool = Query(False),
    from_: str | None = Query(None, alias="from"),
    to: str | None = None,
    settings: Settings = Depends(get_settings_dep),
    elastic: ElasticClient = Depends(get_elastic),
) -> RepresentativeOut:
    """Pick the most-representative event for a detection group.

    Selects the event whose (src_ip, dst_ip, dst_port) tuple is the most
    common across up to 200 events in the cluster, breaking ties by recency.
    Returns the ES ``_id`` to hunt and a human-readable rationale so the UI
    can show the operator which event was chosen and why.

    Bounded by ``webui_grid_timeout_s`` like its sibling list routes. This one
    was the exception, and a grid that accepts connections without answering
    raises nothing for the arms below to catch — so the picker sat on the ES
    client's retry budget (~90 s at shipped defaults) while the analyst waited
    on the button that opens an investigation.
    """
    try:
        async with asyncio.timeout(settings.webui_grid_timeout_s):
            events = await aq.fetch_group_events(
                elastic,
                settings,
                rule_name=rule_name,
                kind=kind,
                time_range=range_,
                severity=severity,
                oql=q,
                size=aq.MAX_EVENTS,
                hide_acked=hide_acked,
                abs_from=from_,
                abs_to=to,
                time_zone=settings.so_timezone,
            )
    except OqlValidationError as exc:
        raise HTTPException(
            status_code=400, detail={"reason": "bad_oql", "hint": str(exc)}
        ) from exc
    except (TimeoutError, TransportError) as exc:
        raise HTTPException(status_code=503, detail=_grid_unavailable(exc)) from exc
    except ApiError as exc:
        raise _es_api_error_http(exc) from exc

    if not events:
        raise HTTPException(
            status_code=404,
            detail={"reason": "no_events", "hint": "No events in window for this rule."},
        )

    rep, matched, reason = _pick_representative(events)
    return RepresentativeOut(
        alert_id=rep.es_id,
        src_ip=rep.src_ip,
        dst_ip=rep.dst_ip,
        dst_port=rep.dst_port,
        matched=matched,
        total=len(events),
        reason=reason,
    )
