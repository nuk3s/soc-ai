"""Alert list / group events / representative-event endpoints."""

from __future__ import annotations

import asyncio
import logging
from collections import Counter

from elastic_transport import TransportError
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
from soc_ai.so_client.elastic import ElasticClient
from soc_ai.store import assignments as assign_svc
from soc_ai.store import detection_overrides as override_svc
from soc_ai.store import investigations as inv_svc
from soc_ai.store.models import Investigation
from soc_ai.webui import alerts_query as aq

_LOGGER = logging.getLogger(__name__)


class AlertEventOut(BaseModel):
    id: str = ""  # es _id — needed by the upcoming per-event selection feature
    src: str
    dst: str
    host: str
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


def _inherited_reason(inv: Investigation) -> str:
    """Human explanation for an inherited verdict — WHICH investigation and WHEN,
    so the analyst can trust (and open) the source rather than seeing an opaque
    'inherited' badge."""
    when = _ago(inv.created_at.isoformat()) if inv.created_at else "?"
    flow = f"{inv.src_ip or '?'} → {inv.dest_ip or '?'}"
    return (
        f"Inherited — same detection, investigated {when} ago on {flow} "
        f"(investigation {inv.id[:8]}…)"
    )


@router.get("/alerts", response_model=list[AlertGroupOut])
async def list_alerts(
    request: Request,
    range_: str = Query("24h", alias="range"),
    severity: str | None = None,
    q: str | None = None,
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
        raise HTTPException(
            status_code=503,
            detail={
                "reason": "grid_unavailable",
                "hint": (
                    "The Security Onion grid (Elasticsearch) is slow or unreachable "
                    "— retry shortly."
                ),
            },
        ) from exc

    # Verdict badge per rule = the rule's STANDING verdict (its latest COMPLETE,
    # verdict-bearing investigation). A later interrupted run (error/cancelled/
    # still-running) must NOT erase that verdict — it only drives the separate
    # "Triaging…" flag. This keeps the group badge consistent with the per-event
    # labels (which already match on complete investigations). "inherited" = the
    # verdict came from a different alert than this group's latest event.
    # badge per rule: (verdict, conf, cross_alert_inherited, inv_id, investigated_pair)
    badges: dict[str, tuple[str, float | None, bool, str, str]] = {}
    owners: dict[str, str] = {}
    verdicts: dict[str, Investigation] = {}
    running_rules: set[str] = set()
    muted_rules: set[str] = set()
    if groups:
        rule_names = [g.rule_name for g in groups]
        async with request.app.state.db_sessionmaker() as db:
            verdicts = await inv_svc.latest_complete_for_rules(db, rule_names)
            latest_any = await inv_svc.latest_for_rules(db, rule_names)
            owners = await assign_svc.owners_for_rules(db, rule_names)
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
                owner=owners.get(g.rule_name),
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
    q: str | None = None,
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
                abs_from=from_,
                abs_to=to,
                time_zone=settings.so_timezone,
            )
    except OqlValidationError as exc:
        raise HTTPException(
            status_code=400, detail={"reason": "bad_oql", "hint": str(exc)}
        ) from exc
    except (TimeoutError, TransportError) as exc:
        raise HTTPException(
            status_code=503,
            detail={
                "reason": "grid_unavailable",
                "hint": (
                    "The Security Onion grid (Elasticsearch) is slow or unreachable "
                    "— retry shortly."
                ),
            },
        ) from exc

    # Three batched DB lookups — no per-event queries (no N+1).
    # 1. Direct: events whose exact es_id was investigated.
    # 2. Pair: events matching a (rule, src_ip, dst_ip) from a complete investigation.
    # 3. Rule: any complete investigation for this rule (rule-level fallback).
    async with request.app.state.db_sessionmaker() as db:
        direct = await inv_svc.latest_for_alerts(db, [e.es_id for e in events])
        ip_events = [e for e in events if e.src_ip and e.dst_ip]
        pairs: list[tuple[str, str, str]] = [
            (rule_name, e.src_ip, e.dst_ip)  # type: ignore[misc]
            for e in ip_events
        ]
        pair_map = await inv_svc.latest_for_pairs(
            db, pairs, window_days=settings.webui_inherit_window_days
        )
        # Rule-level fallback uses the rule's STANDING verdict (latest complete,
        # verdict-bearing) — same source as the group badge — so every event in a
        # triaged group inherits consistently. (Using the most-recent run of ANY
        # status would skip the fallback whenever a later run errored/was
        # cancelled, leaving some events mislabelled "untriaged".)
        rule_map = await inv_svc.latest_complete_for_rules(db, [rule_name])
    rule_inv = rule_map.get(rule_name)

    out: list[AlertEventOut] = []
    for e in events:
        base = AlertEventOut(
            id=e.es_id,
            src=e.src,
            dst=e.dst,
            host=e.host,
            sev=_sev(e.severity),
            port=e.dst_port,
            ts=e.timestamp,
            ago=_ago(e.timestamp),
        )
        direct_inv = direct.get(e.es_id)
        pair_inv = pair_map.get((rule_name, e.src_ip, e.dst_ip)) if e.src_ip and e.dst_ip else None
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


def _pick_representative(
    events: list[aq.AlertEvent],
) -> tuple[aq.AlertEvent, int, str]:
    """Return (event, matched_count, reason) for the most-representative event.

    Selection rule:
    1. Count occurrences of each (src_ip, dst_ip, dst_port) tuple across all
       events that have at least src_ip + dst_ip populated.
    2. Modal tuple wins; ties broken by the most-recent event in that tuple.
    3. Within the winning tuple choose the *newest* event.
    4. If no IP-bearing events exist, fall back to the globally newest event.
    """
    # Only consider events that have both IPs (port may be None).
    ip_events = [e for e in events if e.src_ip and e.dst_ip]
    if not ip_events:
        # Fallback: newest overall.
        newest = max(events, key=lambda e: e.timestamp)
        return (
            newest,
            1,
            "No IP-bearing events in cluster —"
            f" representative = newest overall ({newest.timestamp}).",
        )

    # Count tuples.
    FlowKey = tuple[str | None, str | None, int | None]
    counts: Counter[FlowKey] = Counter((e.src_ip, e.dst_ip, e.dst_port) for e in ip_events)
    # Find the maximum count, then among all tuples with that count pick the one
    # whose most-recent event is latest (tie-break by recency of the tuple).
    max_count = max(counts.values())
    winning_tuples = [t for t, c in counts.items() if c == max_count]

    def _tuple_newest_ts(tup: FlowKey) -> str:
        return max(
            (e.timestamp for e in ip_events if (e.src_ip, e.dst_ip, e.dst_port) == tup),
            default="",
        )

    winning_tuple = max(winning_tuples, key=_tuple_newest_ts)
    src_ip, dst_ip, dst_port = winning_tuple

    # Pick the newest event within the winning tuple.
    candidates = [e for e in ip_events if (e.src_ip, e.dst_ip, e.dst_port) == winning_tuple]
    representative = max(candidates, key=lambda e: e.timestamp)

    dst_label = f"{dst_ip}:{dst_port}" if dst_port is not None else str(dst_ip)
    reason = (
        f"Most common flow {src_ip} → {dst_label}"
        f" — {max_count} of {len(events)} events;"
        f" representative = newest ({representative.timestamp})."
    )
    return representative, max_count, reason


@router.get("/alerts/representative", response_model=RepresentativeOut)
async def get_representative(
    rule_name: str,
    kind: str = "suricata",
    range_: str = Query(aq.DEFAULT_RANGE, alias="range"),
    severity: str | None = None,
    q: str | None = None,
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
    """
    try:
        events = await aq.fetch_group_events(
            elastic,
            settings,
            rule_name=rule_name,
            kind=kind,
            time_range=range_,
            severity=severity,
            oql=q,
            size=aq.MAX_EVENTS,
            abs_from=from_,
            abs_to=to,
            time_zone=settings.so_timezone,
        )
    except OqlValidationError as exc:
        raise HTTPException(
            status_code=400, detail={"reason": "bad_oql", "hint": str(exc)}
        ) from exc

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
