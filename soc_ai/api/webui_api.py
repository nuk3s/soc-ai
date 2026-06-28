"""JSON API for the React frontend, mounted at ``/api/v1``.

These endpoints mirror the shapes in ``frontend/src/lib/types.ts`` so the SPA's
``src/lib/api.ts`` can ``fetch()`` them with no screen changes. The whole router
is guarded by :func:`require_api_auth` (session cookie OR ``scai_`` bearer),
exactly like the rest of the JSON API — when ``API_AUTH_REQUIRED`` is off (lab
default) it's open.

Mutations (approve/reject, chat, auto-triage, config save, action execution)
go through a shared service layer (``soc_ai.webui`` managers) so every write
flows through one code path.
"""

from __future__ import annotations

import asyncio
import json
import logging
import secrets
import time
from collections import Counter
from datetime import UTC, datetime
from typing import Any

from elastic_transport import TransportError
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, SecretStr, ValidationError
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from soc_ai.api import agent_tools as agent_tools_svc
from soc_ai.api.approvals import WRITE_TOOLS, apply_approval, execute_write_tool
from soc_ai.api.data_sources import DataSourceOut, collect_data_sources
from soc_ai.api.deps import get_elastic, get_settings_dep
from soc_ai.api.security import identify_caller, require_api_auth, require_csrf_safe
from soc_ai.config import Settings
from soc_ai.errors import OqlValidationError
from soc_ai.so_client.elastic import ElasticClient
from soc_ai.store import assignments as assign_svc
from soc_ai.store import auth as auth_svc
from soc_ai.store import chat as chat_svc
from soc_ai.store import config_overrides as cfg_svc
from soc_ai.store import internal_identifiers as ids_store
from soc_ai.store import investigations as inv_svc
from soc_ai.store.models import ApiToken, ConfigOverride, Investigation
from soc_ai.webui import alerts_query as aq
from soc_ai.webui import autotriage as at
from soc_ai.webui import chat_manager, hunt_manager, probes, timeline_labels
from soc_ai.webui.deps import current_user

_LOGGER = logging.getLogger(__name__)

router = APIRouter(dependencies=[Depends(require_api_auth), Depends(require_csrf_safe)])

# Pre-auth endpoints (login / logout) — NOT covered by require_api_auth.
# Mounted under the same /api/v1 prefix in main.py but on a separate router
# so the blanket auth dependency above doesn't apply.
open_router = APIRouter()


class LoginIn(BaseModel):
    username: str
    password: str


def _request_is_https(request: Request) -> bool:
    """True when the client connection is HTTPS, honoring a TLS-terminating proxy.

    The canonical deployment terminates TLS in uvicorn (``request.url.scheme`` is
    already ``https``). When the app sits behind a reverse proxy that terminates
    TLS and forwards over plain HTTP, ``request.url.scheme`` reports ``http`` but
    the proxy sets ``X-Forwarded-Proto: https`` — honor that so the ``Secure``
    cookie flag is still applied. Plain-HTTP dev (no forwarded header, scheme
    ``http``) stays False so local login isn't broken by an unsendable Secure
    cookie.
    """
    if request.url.scheme == "https":
        return True
    forwarded = request.headers.get("x-forwarded-proto", "")
    # May be a comma-separated list (proxy chain); the left-most is the client.
    return forwarded.split(",")[0].strip().lower() == "https"


@open_router.post("/login")
async def api_login(body: LoginIn, request: Request) -> JSONResponse:
    """Authenticate and set the session cookie.  No auth gate — this IS the gate.

    A per-(client IP, username) sliding-window throttle locks out further
    attempts after repeated failures to blunt online password brute-forcing.
    """
    settings = request.app.state.settings
    client_ip = request.client.host if request.client else "?"
    throttle = auth_svc.login_throttle
    ip_throttle = auth_svc.login_ip_throttle  # per-IP across all usernames (spray)
    if throttle.is_locked(client_ip, body.username) or ip_throttle.is_locked(client_ip, ""):
        _LOGGER.warning(
            "login locked out for user=%r from ip=%s (too many failed attempts)",
            body.username,
            client_ip,
        )
        raise HTTPException(
            status_code=429,
            detail={
                "reason": "too_many_attempts",
                "hint": "Too many failed logins; try again later.",
            },
        )
    async with request.app.state.db_sessionmaker() as db:
        user = await auth_svc.authenticate(db, body.username, body.password)
        if user is None:
            locked = throttle.record_failure(client_ip, body.username)
            ip_throttle.record_failure(client_ip, "")  # count toward the per-IP spray limit
            if locked:
                _LOGGER.warning(
                    "login throttle engaged for user=%r from ip=%s after repeated failures",
                    body.username,
                    client_ip,
                )
            raise HTTPException(
                status_code=401,
                detail={"reason": "invalid_credentials", "hint": "Invalid username or password"},
            )
        throttle.clear(client_ip, body.username)
        raw = await auth_svc.create_session(db, user, settings.session_ttl_hours)
    resp = JSONResponse({"ok": True, "username": user.username, "role": user.role})
    resp.set_cookie(
        auth_svc.SESSION_COOKIE,
        raw,
        httponly=True,  # always: keep the session token out of reach of JS / XSS
        samesite="lax",  # blocks cross-site cookie replay (CSRF) on state-changing nav
        # HTTPS-only flag, gated on the scheme so plain-HTTP dev login still works.
        secure=_request_is_https(request),
        max_age=settings.session_ttl_hours * 3600,
        path="/",
    )
    return resp


@open_router.post("/logout")
async def api_logout(request: Request) -> JSONResponse:
    """Delete the current session cookie (best-effort — no CSRF needed to log yourself out)."""
    raw = request.cookies.get(auth_svc.SESSION_COOKIE)
    if raw is not None:
        async with request.app.state.db_sessionmaker() as db:
            await auth_svc.delete_session(db, raw)
    resp = JSONResponse({"ok": True})
    resp.delete_cookie(auth_svc.SESSION_COOKIE, path="/")
    return resp


async def require_admin_api(request: Request) -> None:
    """Admin gate for sensitive reads (config). No-op when API auth is off (dev)."""
    if not request.app.state.settings.api_auth_required:
        return
    user = await current_user(request)
    if user is None or user.role != "admin":
        raise HTTPException(status_code=403, detail={"reason": "admin_required"})


# The React unions are narrower than what the backend can emit; coerce to them
# so the client never sees a value outside its TypeScript types.
_FE_SEV = {"critical", "high", "medium", "low"}
_FE_KIND = {"suricata", "sigma", "notice"}


def _sev(value: str | None) -> str:
    v = (value or "").lower()
    return v if v in _FE_SEV else "low"


def _kind(value: str | None) -> str:
    v = (value or "").lower()
    return v if v in _FE_KIND else "suricata"


def _verdict(value: str | None) -> str:
    return value or "untriaged"


def _ago(ts: str) -> str:
    """ES ``@timestamp`` (ISO-8601) → a short relative label (now/3m/2h/5d)."""
    if not ts:
        return ""
    try:
        dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except ValueError:
        return ts
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    secs = (datetime.now(UTC) - dt).total_seconds()
    if secs < 60:
        return "now"
    if secs < 3600:
        return f"{int(secs // 60)}m"
    if secs < 86400:
        return f"{int(secs // 3600)}h"
    return f"{int(secs // 86400)}d"


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


def _inherited_reason(inv: Investigation) -> str:
    return f"Inherited — same detection, investigated on {inv.src_ip or '?'} → {inv.dest_ip or '?'}"


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
    settings: Settings = Depends(get_settings_dep),
    elastic: ElasticClient = Depends(get_elastic),
) -> list[AlertGroupOut]:
    """Grouped-by-detection rows for the Alerts console (events loaded lazily)."""
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

    # verdict badge per rule: the rule's most-recent investigation. "inherited"
    # when that verdict came from a different alert than this group's latest one
    # (mirrors the HTMX _alerts_context derivation).
    # badge per rule: (verdict, conf, cross_alert_inherited, inv_id, investigated_pair, is_running)
    badges: dict[str, tuple[str, float | None, bool, str, str, bool]] = {}
    owners: dict[str, str] = {}
    latest: dict[str, Investigation] = {}
    if groups:
        rule_names = [g.rule_name for g in groups]
        async with request.app.state.db_sessionmaker() as db:
            latest = await inv_svc.latest_for_rules(db, rule_names)
            owners = await assign_svc.owners_for_rules(db, rule_names)
        latest_ids = {g.rule_name: g.latest_id for g in groups}
        for rule, inv in latest.items():
            is_running = inv.status == "running"
            inherited = inv.status == "complete" and inv.alert_es_id != latest_ids.get(rule)
            pair = f"{inv.src_ip or '?'} → {inv.dest_ip or '?'}"
            badges[rule] = (
                _verdict(inv.verdict),
                inv.confidence,
                inherited,
                inv.id,
                pair,
                is_running,
            )

    auto = at.get_status(request.app.state)
    out: list[AlertGroupOut] = []
    for g in groups:
        verdict, conf, inherited, inv_id, pair, is_running = badges.get(
            g.rule_name, ("untriaged", None, False, "", "", False)
        )
        # A verdict is reached by investigating ONE representative alert and then
        # applied to the whole group — so the other events inherit it. Surface
        # that coverage (the analyst should know it's a sampled verdict), and
        # flag the stronger case where even the representative differs.
        reason: str | None = None
        _inv = latest.get(g.rule_name)
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
                events=[],
                invId=inv_id or None,
                inheritedReason=reason,
                # pending_rules is dual-keyed: the global sweep stores rule names,
                # but the multi-select path stores alert ES ids (each group's
                # latest_id — plan_targets_for_ids leaves rule_name blank). Match
                # on either so EVERY queued group in the batch shows "Triaging…",
                # not just the one the sequential worker is running right now.
                triaging=is_running
                or (
                    auto.active
                    and (
                        g.rule_name in auto.pending_rules
                        or (g.latest_id is not None and g.latest_id in auto.pending_rules)
                    )
                ),
                ackedCount=g.acked_count,
                escalatedCount=g.escalated_count,
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
        rule_map = await inv_svc.latest_for_rules(db, [rule_name])
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
        if direct_inv is not None:
            base.investigated = True
            base.invId = direct_inv.id
            base.inheritedReason = None
        elif e.src_ip and e.dst_ip:
            pair_inv = pair_map.get((rule_name, e.src_ip, e.dst_ip))
            if pair_inv is not None:
                base.investigated = False
                base.invId = pair_inv.id
                base.inheritedReason = _inherited_reason(pair_inv)
            elif rule_inv is not None and rule_inv.status == "complete":
                base.investigated = False
                base.invId = rule_inv.id
                base.inheritedReason = _inherited_reason(rule_inv)
        elif rule_inv is not None and rule_inv.status == "complete":
            base.investigated = False
            base.invId = rule_inv.id
            base.inheritedReason = _inherited_reason(rule_inv)
        out.append(base)
    return out


_ACK_CAP = 200  # maximum events acknowledged per ack-group call
_ACK_CONCURRENCY = 8  # bounded fan-out for bulk ack to keep ES/SO round-trips parallel-but-capped


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


class AckGroupIn(BaseModel):
    rule_name: str
    kind: str = "suricata"
    range: str = aq.DEFAULT_RANGE
    q: str | None = None
    severity: str | None = None
    from_: str | None = None
    to: str | None = None

    model_config = {"populate_by_name": True}


class AckGroupOut(BaseModel):
    acked: int
    failed: int
    total: int
    capped: bool = False


@router.post("/alerts/ack-group", response_model=AckGroupOut)
async def ack_group(
    request: Request,
    body: AckGroupIn,
    settings: Settings = Depends(get_settings_dep),
    elastic: ElasticClient = Depends(get_elastic),
) -> AckGroupOut:
    """Acknowledge all events for a detection group in Security Onion.

    Fetches up to ``_ACK_CAP`` events matching the rule+filters and calls
    ``ack_alert`` for each via the write-tool path.  Returns counts of
    successes, failures, and whether the cap was hit.
    """
    caller = await identify_caller(request)
    try:
        events = await aq.fetch_group_events(
            elastic,
            settings,
            rule_name=body.rule_name,
            kind=body.kind,
            time_range=body.range,
            severity=body.severity,
            oql=body.q,
            size=_ACK_CAP + 1,  # fetch one extra to detect capping
            abs_from=body.from_,
            abs_to=body.to,
            time_zone=settings.so_timezone,
            hide_acked=True,
        )
    except OqlValidationError as exc:
        raise HTTPException(
            status_code=400, detail={"reason": "bad_oql", "hint": str(exc)}
        ) from exc

    capped = len(events) > _ACK_CAP
    events = events[:_ACK_CAP]

    if not events:
        return AckGroupOut(acked=0, failed=0, total=0)

    acked, failed = await _ack_many(
        request,
        [ev.es_id for ev in events],
        session_id=f"ack-group:{body.rule_name}",
        caller=caller,
    )

    total = acked + failed
    if capped:
        logging.getLogger(__name__).warning(
            "ack-group capped at %d events for rule %r (caller=%s)",
            _ACK_CAP,
            body.rule_name,
            caller,
        )

    return AckGroupOut(acked=acked, failed=failed, total=total, capped=capped)


class AckEventsIn(BaseModel):
    es_ids: list[str]


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


class AssignOut(BaseModel):
    rule_name: str
    owner: str | None


@router.post("/alerts/assign", response_model=AssignOut)
async def assign_alert(
    request: Request,
    body: AssignIn,
) -> AssignOut:
    """Persist (or clear) the owner for a detection rule.

    When ``unassign`` is False the caller is resolved via
    :func:`~soc_ai.api.security.identify_caller` and stored as the owner.
    When ``unassign`` is True the row is removed.  The owner value is a plain
    username when the caller is authenticated via session, or ``token:<name>``
    when using a bearer token, or ``"anonymous"`` when API auth is off.
    """
    async with request.app.state.db_sessionmaker() as db:
        if body.unassign:
            await assign_svc.clear_assignment(db, body.rule_name)
            return AssignOut(rule_name=body.rule_name, owner=None)
        owner = await identify_caller(request)
        await assign_svc.set_assignment(db, body.rule_name, owner)
    return AssignOut(rule_name=body.rule_name, owner=owner)


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


# ── Investigations ─────────────────────────────────────────────────────────

# Frontend status union: running | complete | awaiting | error | cancelled.
_STATUS = {
    "running": "running",
    "complete": "complete",
    "error": "error",
    "cancelled": "cancelled",
    "awaiting": "awaiting",
}


def _row_status(inv: Investigation) -> str:
    """Effective display status for an investigation row.

    An unknown stored status falls back to 'error' (never silently 'complete'),
    and a finished run that produced NO verdict is reported as 'error' — it never
    reached a triage decision, so labelling it 'complete' would be a lie (the
    verdict shows 'untriaged'). A real verdict — including needs_more_info — keeps
    the stored status.
    """
    status = _STATUS.get(inv.status, "error")
    if status == "complete" and not (inv.verdict or "").strip():
        return "error"
    return status


class InvestigationRowOut(BaseModel):
    id: str
    name: str
    kind: str
    verdict: str
    conf: float | None = None
    host: str
    status: str
    when: str
    ts: str = ""
    chatCount: int = 0


def _elapsed_sec(inv: Investigation) -> int:
    created = inv.created_at
    if created.tzinfo is None:
        created = created.replace(tzinfo=UTC)
    end = inv.finished_at or datetime.now(UTC)
    if end.tzinfo is None:
        end = end.replace(tzinfo=UTC)
    return max(0, int((end - created).total_seconds()))


def _elapsed(inv: Investigation) -> str:
    s = _elapsed_sec(inv)
    return f"{s}s" if s < 60 else f"{s // 60}m {s % 60}s"


def _row(inv: Investigation, chat_count: int = 0) -> InvestigationRowOut:
    return InvestigationRowOut(
        id=inv.id,
        name=inv.rule_name or "Investigation",
        kind="suricata",
        verdict=_verdict(inv.verdict),
        conf=inv.confidence,
        host=inv.src_ip or "—",
        status=_row_status(inv),
        when=_ago(inv.created_at.isoformat()),
        ts=inv.created_at.isoformat(),
        chatCount=chat_count,
    )


@router.get("/investigations", response_model=list[InvestigationRowOut])
async def list_investigations(
    request: Request,
    status: str | None = None,
    limit: int = 100,
) -> list[InvestigationRowOut]:
    if status not in (None, "running", "complete", "error", "cancelled", "awaiting"):
        status = None
    async with request.app.state.db_sessionmaker() as db:
        rows = await inv_svc.list_recent(db, status=status, limit=min(max(limit, 1), 500))
        chat_counts = await chat_svc.counts_for(db, [inv.id for inv in rows])
    return [_row(inv, chat_counts.get(inv.id, 0)) for inv in rows]


# ── Investigation detail ───────────────────────────────────────────────────

_TL_GROUP = {
    "session_start": "Prefetch & pivots",
    "investigation_loop_entered": "Prefetch & pivots",
    "alert_context": "Indicator enrichment",
    "enriched_alert_context": "Indicator enrichment",
    "tool_call": "Tool calls",
    "tool_result": "Tool calls",
    "model_response": "Tool calls",
    "decision_template_match": "Decision",
    "template_ceiling": "Decision",
    "triage_report": "Decision",
    "approval_request": "Decision",
    "approval_required": "Decision",
    "citation_validation": "Validators",
    "citation_cap": "Validators",
    "error": "Validators",
}
_TL_SKIP = {"usage", "done", "tool_result", "model_response", "synth_round1_skipped"}
_PORT_PROTO = {21: "FTP", 22: "SSH", 53: "DNS", 80: "HTTP", 443: "TLS", 445: "SMB", 3389: "RDP"}
_ACTION_TITLE = {
    "ack_alert": "Acknowledge alert",
    "escalate_to_case": "Escalate to case",
    "add_case_comment": "Add case comment",
}
_ACTION_TAG = {"ack_alert": "ack", "escalate_to_case": "escalate", "add_case_comment": "comment"}


def _tl_group(kind: str) -> str:
    if kind.startswith("oracle"):
        return "Oracle"
    return _TL_GROUP.get(kind, "Tool calls")


def _compact(obj: Any, limit: int = 160) -> str:
    s = obj if isinstance(obj, str) else json.dumps(obj, default=str, ensure_ascii=False)
    return s if len(s) <= limit else s[: limit - 1] + "…"


def _ep(ip: Any, port: Any) -> str:
    if not ip:
        return "—"
    return f"{ip}:{port}" if port not in (None, "") else str(ip)


def _proto(alert: dict[str, Any]) -> str:
    p = alert.get("destination_port") or alert.get("source_port")
    try:
        return _PORT_PROTO.get(int(p), "TCP") if p is not None else "—"
    except (TypeError, ValueError):
        return "—"


def _alert_meta(
    alert: dict[str, Any], host_profile: dict[str, int], inv: Investigation
) -> dict[str, Any] | None:
    """The triggering detection's raw facts, from the stored alert context."""
    if not alert:
        return None
    rule = alert.get("rule_name") or inv.rule_name or "—"
    return {
        "id": inv.alert_es_id or "",
        "rule": rule,
        "sid": alert.get("rule_uuid"),
        "classtype": alert.get("classtype"),
        "category": alert.get("event_category"),
        "src": _ep(alert.get("source_ip"), alert.get("source_port")),
        "dst": _ep(alert.get("destination_ip"), alert.get("destination_port")),
        "proto": _proto(alert),
        "action": alert.get("alert_action") or alert.get("event_action") or "—",
        "firstSeen": "—",
        "lastSeen": inv.created_at.isoformat(sep=" ", timespec="seconds"),
        "count": int(host_profile.get(rule, 1) or 1),
    }


def _host_signals(host_profile: dict[str, int]) -> list[dict[str, Any]]:
    """The host's other alert activity (rule -> count), ranked by volume. The
    tone reflects relative volume on the host, not absolute rule severity."""
    if not host_profile:
        return []
    items = sorted(host_profile.items(), key=lambda kv: kv[1], reverse=True)[:6]
    mx = max((c for _, c in items), default=1) or 1
    out: list[dict[str, Any]] = []
    for rule, cnt in items:
        ratio = cnt / mx
        if ratio > 0.8:
            tone = "critical"
        elif ratio > 0.5:
            tone = "high"
        elif ratio > 0.25:
            tone = "medium"
        else:
            tone = "low"
        out.append(
            {
                "time": "",
                "label": rule,
                "tone": tone,
                "w": max(6, int(100 * ratio)),
                "sev": f"{cnt}×",  # noqa: RUF001  (count multiplier badge)
            }
        )
    return out


def _entity_graph(
    alert: dict[str, Any], enrichments: dict[str, Any], inv: Investigation
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], str | None]:
    """A real (if small) blast-radius graph: the host, the peers it contacted,
    and which of those enrichment flagged as malicious."""
    src = alert.get("source_ip") or inv.src_ip
    dst = alert.get("destination_ip") or inv.dest_ip
    label = alert.get("host_name") or src
    if not src:
        return [], [], None
    nodes: list[dict[str, Any]] = [
        {
            "id": str(src),
            "x": 20,
            "y": 50,
            "kind": "compromised" if inv.verdict == "true_positive" else "host",
            "label": str(label or src),
        }
    ]
    peers: list[str] = []
    if dst and dst != src:
        peers.append(str(dst))
    for ind in enrichments:
        if str(ind) != str(src) and str(ind) not in peers:
            peers.append(str(ind))
    peers = peers[:5]
    edges: list[dict[str, Any]] = []
    flagged = 0
    n = len(peers)
    for i, ip in enumerate(peers):
        enr = enrichments.get(ip) or {}
        bad = bool(enr.get("blocklist_hits") or enr.get("misp_hits"))
        internal = bool(enr.get("internal"))
        if bad:
            flagged += 1
        y = 50 if n <= 1 else int(18 + 64 * i / (n - 1))
        node_kind = "c2" if bad else "dc" if internal else "host"
        nodes.append({"id": ip, "x": 78, "y": y, "kind": node_kind, "label": ip})
        edges.append({"from": str(src), "to": ip, "kind": "beacon" if bad else "flow"})
    note = f"{label or src} contacted {n} peer(s)" + (
        f"; {flagged} flagged malicious by enrichment" if flagged else ""
    )
    return nodes, edges, note


# Friendly nouns for the read tools so a timeline step says what was checked.
_TOOL_NOUN = {
    "t_enrich_ip": "IP reputation",
    "t_enrich_domain": "Domain reputation",
    "t_enrich_hash": "File-hash reputation",
    "t_query_events_oql": "Event search",
    "t_query_zeek_logs": "Zeek logs",
    "t_query_cases": "Cases",
    "t_query_detections": "Detections",
    "t_get_playbooks": "Playbooks",
    "t_lookup_runbook": "Runbook",
    "t_get_pcap": "PCAP",
    "t_web_search": "Web search",
    "t_crawl_page": "Page fetch",
    "t_get_alert_context": "Alert context",
    "final_result": "Final synthesis",
}
# Display labels for decision-template ids (don't presume the verdict in the name).
_TEMPLATE_LABELS = {"clean_internal_traffic": "internal traffic"}


def _humanize_id(s: str | None) -> str:
    return (s or "").removeprefix("t_").replace("_", " ").strip() or "tool"


def _template_label(tid: str | None) -> str:
    return _TEMPLATE_LABELS.get(tid or "", _humanize_id(tid))


def _tool_outcome(result: Any) -> str:
    """A short, tool-aware outcome — the point of the step (vs 'total: 0')."""
    if result is None:
        return "running…"
    if isinstance(result, list):
        return "no results" if not result else f"{len(result)} result(s)"
    if isinstance(result, str):
        return _compact(result, 80)
    if not isinstance(result, dict):
        return _compact(result, 80)
    # enrichment result
    if {"blocklist_hits", "misp_hits", "indicator"} & set(result):
        bl = result.get("blocklist_hits") or []
        misp = result.get("misp_hits") or []
        if bl or misp:
            srcs = [str(h["source"]) for h in bl if isinstance(h, dict) and h.get("source")]
            return "flagged malicious" + (f" ({', '.join(srcs)})" if srcs else "")
        # A miss is a COVERAGE statement, not a verdict — say so precisely.
        return "internal address" if result.get("internal") else "no blocklist/MISP match"
    # ES query / zeek result
    if result.get("prefetch_already_has_this"):
        return "already in alert context"
    if "total" in result or "hits" in result:
        total = result.get("total_display") or result.get("total", 0)
        return f"{total} match" if str(total) == "1" else f"{total} matches"
    # web_search / list-shaped results carrying a count
    if "result_count" in result:
        n = result.get("result_count", 0)
        return "no results" if n == 0 else f"{n} result" if n == 1 else f"{n} results"
    for k in ("summary", "verdict", "status", "note", "hint"):
        if result.get(k):
            return _compact(result[k], 90)
    return _compact({k: result[k] for k in list(result)[:3]}, 110)


def _tool_step(tool_name: str, args: dict[str, Any], result: Any) -> tuple[str, str]:
    """Title carries the point (tool + outcome); detail carries the useful query."""
    noun = _TOOL_NOUN.get(tool_name, _humanize_id(tool_name).capitalize())
    outcome = _tool_outcome(result)
    title = f"{noun}: {outcome}"
    detail = f"query: {_compact(args, 200)}" if args else "no arguments"
    if isinstance(result, dict):
        extra = []
        geo = result.get("geoip") if isinstance(result.get("geoip"), dict) else None
        asn = result.get("asn") if isinstance(result.get("asn"), dict) else None
        if geo and geo.get("country_name"):
            extra.append(str(geo["country_name"]))
        if asn and asn.get("asn_org"):
            extra.append(str(asn["asn_org"]))
        if result.get("cloud_provider"):
            extra.append(str(result["cloud_provider"]))
        if result.get("hint"):
            extra.append(_compact(result["hint"], 120))
        if extra:
            detail += "\n" + " · ".join(extra)
    return title, detail


def _detail_for(kind: str, p: dict[str, Any] | None, result: Any = None) -> str:
    """A human-readable details+outcome line per event (vs a raw JSON dump)."""
    p = p or {}
    if kind in ("enriched_alert_context", "alert_context"):
        enr = p.get("enrichments") or {}
        prof = p.get("host_alert_profile") or {}
        return (
            f"Loaded the alert and enriched {len(enr)} indicator(s); the host shows "
            f"{len(prof)} distinct alert type(s) in the window."
        )
    if kind == "decision_template_match":
        if p.get("matched"):
            return (
                f"Matched the '{_template_label(p.get('template_id'))}' pattern → "
                f"{p.get('verdict')} ({p.get('confidence')}). {p.get('rationale', '')}".strip()
            )
        return "No pattern matched — ran a full tool-using investigation."
    if kind == "investigation_loop_entered":
        return (
            f"{p.get('reason', '')} (round-1 was {p.get('round1_verdict')} @ "
            f"{p.get('round1_confidence')})".strip()
        )
    if kind == "triage_report":
        return f"{p.get('verdict')} ({p.get('confidence')})\n{_compact(p.get('summary', ''), 300)}"
    if kind == "citation_validation":
        c = p.get("counts") or {}
        valid, total, cov = c.get("valid", "?"), p.get("total", "?"), p.get("coverage_ratio")
        return f"{valid}/{total} citations valid (coverage {cov})"
    if kind == "citation_cap":
        return (
            f"confidence {p.get('original_confidence')} → {p.get('capped_confidence')} "
            "to respect citation coverage"
        )
    if kind == "investigation_transcript":
        ev = p.get("evidence") or []
        return f"{p.get('tentative_summary', '')}\nevidence gathered: {len(ev)} item(s)".strip()
    if kind == "error":
        return _compact(p.get("message") or p.get("error") or "", 240)
    if kind == "session_start":
        return f"pipeline: {p.get('pipeline', '?')}"
    return _compact(p, 220)


class RecommendedActionOut(BaseModel):
    id: str
    title: str
    tag: str
    rationale: str
    token: str | None = None
    pending: bool = False


class TimelineStepOut(BaseModel):
    id: str
    group: str
    title: str
    time: str = ""
    detail: str = ""


class ChatMessageOut(BaseModel):
    role: str
    text: str
    tools: str | None = None
    messageId: int | None = None
    kind: str | None = None
    validation: str | None = None
    objection: str | None = None
    token: str | None = None
    applied: bool | None = None
    proposal: dict[str, Any] | None = None


class InvMetaOut(BaseModel):
    model: str
    oracle: str | None = None
    ranBy: str
    ranAt: str
    toolCalls: int
    pivots: int


class OracleOut(BaseModel):
    escalated: bool = True
    reason: str | None = None
    localVerdict: str | None = None
    localConfidence: float | None = None
    oracleVerdict: str | None = None
    oracleConfidence: float | None = None
    model: str | None = None
    redacted: bool = False
    redactionNote: str | None = None
    changed: bool = False  # oracleVerdict differs from localVerdict


class InvestigationOut(BaseModel):
    id: str
    groupId: str
    name: str
    kind: str
    host: str
    ip: str
    verdict: str
    conf: float
    rationale: str
    summary: list[dict[str, Any]]
    status: str
    elapsedLabel: str
    elapsedSec: int = 0
    actions: list[RecommendedActionOut]
    timeline: list[TimelineStepOut]
    nodes: list[dict[str, Any]] = []
    edges: list[dict[str, Any]] = []
    seedChat: list[ChatMessageOut] = []
    meta: InvMetaOut | None = None
    oracle: OracleOut | None = None
    sev: str | None = None
    alert: dict[str, Any] | None = None
    hostContext: list[dict[str, Any]] = []
    graphNote: str | None = None
    openQuestions: list[str] = []
    resolution: dict[str, Any] | None = None
    validatorNote: str | None = None


def _build_actions(
    events: list[Any], report: dict[str, Any], pending_tokens: set[Any]
) -> list[RecommendedActionOut]:
    """Recommended actions: prefer live approval tokens, else report recommendations."""
    approval_events = [e for e in events if e.kind in ("approval_request", "approval_required")]
    out: list[RecommendedActionOut] = []
    if approval_events:
        for i, ev in enumerate(approval_events):
            tok = ev.payload.get("token")
            tn = ev.payload.get("tool_name", "")
            out.append(
                RecommendedActionOut(
                    id=tok or f"a{i}",
                    title=_ACTION_TITLE.get(tn, tn or "Action"),
                    tag=_ACTION_TAG.get(tn, "comment"),
                    rationale=ev.payload.get("rationale", ""),
                    token=tok,
                    pending=tok in pending_tokens if tok else False,
                )
            )
        return out
    for i, a in enumerate(report.get("recommended_actions", []) or []):
        tn = a.get("tool_name", "")
        out.append(
            RecommendedActionOut(
                id=f"a{i}",
                title=_ACTION_TITLE.get(tn, tn or "Action"),
                tag=_ACTION_TAG.get(tn, "comment"),
                rationale=a.get("rationale", ""),
            )
        )
    return out


def _build_oracle(events: list[Any]) -> OracleOut | None:
    """Scan event stream for oracle_escalation / oracle_adjudication and build OracleOut.

    Returns None when neither event kind is present (Oracle was not consulted).
    If only oracle_escalation exists (Oracle was called but errored before returning),
    the returned OracleOut has escalated=True but oracleVerdict=None.
    """
    esc_payload: dict[str, Any] | None = None
    adj_payload: dict[str, Any] | None = None
    for e in events:
        if e.kind == "oracle_escalation":
            esc_payload = e.payload or {}
        elif e.kind == "oracle_adjudication":
            adj_payload = e.payload or {}
    if esc_payload is None and adj_payload is None:
        return None

    reason = (esc_payload or {}).get("reason")
    local_verdict = (esc_payload or {}).get("local_verdict")
    local_confidence = (esc_payload or {}).get("local_confidence")
    oracle_verdict = (adj_payload or {}).get("oracle_verdict")
    oracle_confidence = (adj_payload or {}).get("oracle_confidence")
    oracle_model = (adj_payload or {}).get("oracle_model")
    redaction = (adj_payload or {}).get("redaction")
    redacted = bool(redaction)
    redaction_note = redaction if redacted else None
    changed = bool(oracle_verdict and local_verdict and oracle_verdict != local_verdict)
    return OracleOut(
        escalated=True,
        reason=reason,
        localVerdict=local_verdict,
        localConfidence=local_confidence,
        oracleVerdict=oracle_verdict,
        oracleConfidence=oracle_confidence,
        model=oracle_model,
        redacted=redacted,
        redactionNote=redaction_note,
        changed=changed,
    )


def _build_timeline(events: list[Any]) -> tuple[list[TimelineStepOut], int, int, bool]:
    """Build the analyst timeline (what + details + outcome per step) and the
    tool-call / pivot counts. tool_result events are merged into their tool_call."""
    result_by_call = {
        (e.payload or {}).get("tool_call_id"): (e.payload or {}).get("result")
        for e in events
        if e.kind == "tool_result"
    }
    timeline: list[TimelineStepOut] = []
    tool_calls = pivots = 0
    has_oracle = False
    for e in events:
        if e.kind in _TL_SKIP:
            continue
        p = e.payload or {}
        if e.kind.startswith("oracle"):
            has_oracle = True
        if e.kind == "tool_call":
            tool_calls += 1
            tn = str(p.get("tool_name", ""))
            if "query" in tn or "zeek" in tn or "pcap" in tn:
                pivots += 1
            result = result_by_call.get(p.get("tool_call_id"))
            title, detail = _tool_step(tn, p.get("args") or {}, result)
        elif e.kind == "decision_template_match":
            title = (
                f"Matched pattern: {_template_label(p.get('template_id'))}"
                if p.get("matched")
                else "No pattern matched — ran a full investigation"
            )
            detail = _detail_for(e.kind, p)
        else:
            title = timeline_labels.title_for(e.kind, p)
            detail = _detail_for(e.kind, p)
        timeline.append(
            TimelineStepOut(
                id=f"e{e.sequence}", group=_tl_group(e.kind), title=title, detail=detail
            )
        )
    return timeline, tool_calls, pivots, has_oracle


@router.get("/investigations/{inv_id}", response_model=InvestigationOut)
async def get_investigation(
    request: Request,
    inv_id: str,
    settings: Settings = Depends(get_settings_dep),
) -> InvestigationOut:
    async with request.app.state.db_sessionmaker() as db:
        got = await inv_svc.get_with_events(db, inv_id)
        if got is None:
            # The drawer opens groups by alert es-id — resolve to its latest run.
            by_alert = await inv_svc.latest_for_alerts(db, [inv_id])
            inv0 = by_alert.get(inv_id)
            if inv0 is not None:
                got = await inv_svc.get_with_events(db, inv0.id)
        if got is None:
            raise HTTPException(status_code=404, detail={"reason": "not_found"})
        inv, events = got
        chat = await chat_svc.list_messages(db, inv.id)
    pending_tokens = {p.token for p in await request.app.state.gate.pending()}

    report = inv.report or {}
    actions = _build_actions(events, report, pending_tokens)

    # The enriched-alert-context event carries the alert, the host's alert
    # profile, and indicator enrichments — everything the rail + graph need.
    enr_p: dict[str, Any] = {}
    for e in events:
        if e.kind in ("enriched_alert_context", "alert_context"):
            enr_p = e.payload or {}
            break
    _ao_raw = enr_p.get("alert") or {}
    alert_obj: dict[str, Any] = _ao_raw if isinstance(_ao_raw, dict) else {}
    _hp_raw = enr_p.get("host_alert_profile") or {}
    host_profile: dict[str, Any] = _hp_raw if isinstance(_hp_raw, dict) else {}
    _en_raw = enr_p.get("enrichments") or {}
    enrichments: dict[str, Any] = _en_raw if isinstance(_en_raw, dict) else {}

    timeline, tool_calls, pivots, has_oracle = _build_timeline(events)
    nodes, edges, graph_note = _entity_graph(alert_obj, enrichments, inv)
    summary_text = report.get("summary") or inv.summary or ""
    meta = InvMetaOut(
        model=settings.analyst_model,
        oracle="escalated to Oracle" if has_oracle else "not escalated — local verdict",
        ranBy=inv.started_by or "—",
        ranAt=inv.created_at.isoformat(sep=" ", timespec="seconds"),
        toolCalls=tool_calls,
        pivots=pivots,
    )
    return InvestigationOut(
        id=inv.id,
        groupId=inv.alert_es_id or inv.id,
        name=inv.rule_name or "Investigation",
        kind="suricata",
        host=alert_obj.get("host_name") or inv.src_ip or "—",
        ip=inv.dest_ip or inv.src_ip or "—",
        verdict=_verdict(inv.verdict),
        conf=inv.confidence if inv.confidence is not None else 0.0,
        rationale=inv.rationale or summary_text,
        summary=[{"t": "text", "v": summary_text}],
        status=(
            "investigating"
            if inv.status == "running"
            # Reaped/stuck runs are persisted as ``error`` — surface that to the
            # drawer so it can render a terminal "failed/interrupted" state
            # instead of an empty "complete" verdict.
            else "error"
            if inv.status == "error"
            # Operator-cancelled runs: a distinct terminal state, not a crash.
            else "cancelled"
            if inv.status == "cancelled"
            else "complete"
        ),
        elapsedLabel=_elapsed(inv),
        elapsedSec=_elapsed_sec(inv),
        actions=actions,
        timeline=timeline,
        nodes=nodes,
        edges=edges,
        seedChat=[_chat_msg_out(m) for m in chat],
        meta=meta,
        oracle=_build_oracle(events),
        sev=_sev(alert_obj.get("severity_label")) if alert_obj else None,
        alert=_alert_meta(alert_obj, host_profile, inv),
        hostContext=_host_signals(host_profile),
        graphNote=graph_note,
        openQuestions=report.get("open_questions") or [],
        resolution=report.get("resolution") or None,
        validatorNote=report.get("validator_note") or None,
    )


# ── Config (admin) ─────────────────────────────────────────────────────────

_SETTING_TYPE = {"bool": "toggle", "int": "number", "float": "number", "str": "text", "csv": "text"}


class SettingOut(BaseModel):
    key: str
    help: str
    source: str
    apply: str
    type: str
    value: bool | float | str
    bounds: str | None = None
    options: list[str] | None = None


class SettingGroupOut(BaseModel):
    title: str
    items: list[SettingOut]


class ApiTokenOut(BaseModel):
    id: int
    name: str
    prefix: str
    created: str
    used: str


class ConfigOut(BaseModel):
    groups: list[SettingGroupOut]
    tokens: list[ApiTokenOut]
    dangerHost: str


# ── Danger-zone models ────────────────────────────────────────────────────────


class DangerSettingOut(BaseModel):
    key: str
    label: str
    type: str  # "secret" | "text" | "bool" | "csv"
    isSet: bool  # whether a non-empty value is configured
    source: str  # "env" | "db" | "unset"
    hot: bool  # True = hot-apply, False = restart-required


class SaveDangerIn(BaseModel):
    key: str
    value: str
    confirm: str  # must equal key (typed confirmation)


class ConnTestOut(BaseModel):
    ok: bool
    detail: str


def _setting_value(spec: cfg_svc.SettingSpec, settings: Settings) -> bool | float | str:
    val = getattr(settings, spec.attr, None)
    if spec.type == "csv":
        return ", ".join(str(x) for x in (val or []))
    if spec.type == "bool":
        return bool(val)
    if spec.type in ("int", "float"):
        return val if val is not None else 0
    return "" if val is None else str(val)


def _bounds(spec: cfg_svc.SettingSpec) -> str | None:
    lo, hi = spec.min_value, spec.max_value
    if lo is None and hi is None:
        return None

    def fmt(x: float | None) -> str:
        if x is None:
            return "∞"
        return str(int(x)) if spec.type == "int" and x == int(x) else str(x)

    return f"{fmt(lo)} to {fmt(hi)}"


@router.get("/config", response_model=ConfigOut, dependencies=[Depends(require_admin_api)])
async def get_config(
    request: Request,
    settings: Settings = Depends(get_settings_dep),
) -> ConfigOut:
    async with request.app.state.db_sessionmaker() as db:
        overrides = await cfg_svc.load_overrides(db)
        tokens = (
            (await db.execute(select(ApiToken).order_by(ApiToken.created_at.desc())))
            .scalars()
            .all()
        )

    groups: list[SettingGroupOut] = []
    for section in cfg_svc.SECTION_ORDER:
        items = [
            SettingOut(
                key=spec.key,
                help=spec.help,
                source="db" if spec.key in overrides else "env",
                apply="hot-apply" if spec.hot else "restart",
                type=_SETTING_TYPE.get(spec.type, "text"),
                value=_setting_value(spec, settings),
                bounds=_bounds(spec),
            )
            for spec in cfg_svc.WHITELIST
            if spec.section == section and not spec.danger and not spec.secret
        ]
        if items:
            groups.append(SettingGroupOut(title=section, items=items))

    token_views = [
        ApiTokenOut(
            id=t.id,
            name=t.name,
            prefix="scai_••••",
            created=_ago(t.created_at.isoformat()),
            used=_ago(t.last_used_at.isoformat()) if t.last_used_at else "never",
        )
        for t in tokens
        if not t.revoked
    ]
    return ConfigOut(
        groups=groups, tokens=token_views, dangerHost=str(settings.so_host or "soc-ai")
    )


class DataSourcesOut(BaseModel):
    sources: list[DataSourceOut]


@router.get(
    "/config/data-sources",
    response_model=DataSourcesOut,
    dependencies=[Depends(require_admin_api)],
)
async def get_data_sources(
    settings: Settings = Depends(get_settings_dep),
) -> DataSourcesOut:
    """Every enrichment data source — local feeds + opt-in online lookups — with
    freshness and key/enable status, for the config console's Data Sources panel."""
    return DataSourcesOut(sources=collect_data_sources(settings))


# ── Shell chrome: workspaces + notifications ───────────────────────────────


class WorkspaceOut(BaseModel):
    name: str
    env: str


class NotificationOut(BaseModel):
    id: str
    tone: str
    title: str
    when: str
    href: str | None = None


@router.get("/workspaces", response_model=list[WorkspaceOut])
async def list_workspaces(settings: Settings = Depends(get_settings_dep)) -> list[WorkspaceOut]:
    host = str(settings.so_host or "Security Onion")
    name = host.replace("https://", "").replace("http://", "").rstrip("/") or "Security Onion"
    return [WorkspaceOut(name=name, env="prod")]


@router.get("/notifications", response_model=list[NotificationOut])
async def list_notifications(request: Request) -> list[NotificationOut]:
    out: list[NotificationOut] = []
    for p in await request.app.state.gate.pending():
        inv_id = p.metadata.get("investigation_id") if p.metadata else None
        out.append(
            NotificationOut(
                id=f"approval:{p.token}",
                tone="warn",
                title=f"Action awaiting approval: {p.tool_name}",
                when="",
                href=f"/investigation/{inv_id}" if inv_id else None,
            )
        )
    async with request.app.state.db_sessionmaker() as db:
        running = await inv_svc.list_recent(db, status="running", limit=20)
    for inv in running:
        out.append(
            NotificationOut(
                id=f"inv:{inv.id}",
                tone="accent",
                title=f"Investigating: {inv.rule_name or inv.id}",
                when=_ago(inv.created_at.isoformat()),
                href=f"/investigation/{inv.id}",
            )
        )
    return out[:12]


# ── Hunts ──────────────────────────────────────────────────────────────────
# No saved-hunt backend yet — that arrives with the hunting agent (planned). The
# list is honestly empty; the stat cards reflect real investigation counts.


class HuntStatOut(BaseModel):
    label: str
    value: str
    sub: str
    tone: str


@router.get("/hunts", response_model=list[dict[str, Any]])
async def list_hunts() -> list[dict[str, Any]]:
    return []


@router.get("/hunts/stats", response_model=list[HuntStatOut])
async def hunt_stats(request: Request) -> list[HuntStatOut]:
    async with request.app.state.db_sessionmaker() as db:
        recent = await inv_svc.list_recent(db, status=None, limit=500)
    total = len(recent)
    tp = sum(1 for i in recent if i.verdict == "true_positive")
    running = sum(1 for i in recent if i.status == "running")
    return [
        HuntStatOut(label="Investigations", value=str(total), sub="recent", tone="accent"),
        HuntStatOut(label="True positives", value=str(tp), sub="confirmed", tone="danger"),
        HuntStatOut(label="In progress", value=str(running), sub="running now", tone="warn"),
    ]


# ── Mutations ──────────────────────────────────────────────────────────────
# CSRF: these are same-origin (the SPA at /app calls /api/v1) and the session
# cookie is SameSite=lax, which blocks cross-site cookie-bearing POSTs — the same
# protection the existing /approve JSON route relies on.


class HuntStartIn(BaseModel):
    # Non-blank: an empty id reaches ES as `ids:[""]` and 500s ("Ids can't be empty").
    alert_id: str = Field(min_length=1)


async def _alert_doc_exists(elastic: ElasticClient, settings: Settings, alert_id: str) -> bool:
    """True iff ``alert_id`` resolves to a real ES document.

    Mirrors the ``ids`` lookup ``get_alert_context`` does before fanning out
    pivots. Used to guard ``/hunt`` so a bad id (e.g. an AlertGroup whose
    ``latest_id`` was empty and fell back to the rule NAME, see alerts_query.py
    ``_group_from_bucket`` + the ``id=g.latest_id or g.rule_name`` mapping)
    fails VISIBLY with a 4xx instead of recording a synthetic 0.0 investigation.
    """
    lookup = await elastic.search(
        settings.events_index_pattern,
        {"ids": {"values": [alert_id]}},
        size=1,
    )
    return bool(lookup.hits)


@router.post("/hunt")
async def start_hunt(
    request: Request,
    body: HuntStartIn,
    settings: Settings = Depends(get_settings_dep),
    elastic: ElasticClient = Depends(get_elastic),
) -> dict[str, str]:
    """Start a background investigation for an alert; returns its id immediately.

    The supplied ``alert_id`` must resolve to a real ES document. A group whose
    ``latest_id`` was blank surfaces its RULE NAME as the id (webui_api mapping
    ``g.latest_id or g.rule_name``); hunting that would otherwise SoNotFoundError
    deep in the prefetch and silently persist a degraded needs_more_info/0.0
    investigation. We resolve up front and 404 instead.
    """
    started_by = await identify_caller(request)
    if not await _alert_doc_exists(elastic, settings, body.alert_id):
        raise HTTPException(
            status_code=404,
            detail={
                "reason": "alert_not_found",
                "hint": ("alert not found — it may have aged out; re-open from the alerts list"),
            },
        )
    # Block a duplicate hunt: if one is already running for this alert, send the
    # caller to it instead of spawning a second investigation for the same alert.
    async with request.app.state.db_sessionmaker() as db:
        existing = (await inv_svc.latest_for_alerts(db, [body.alert_id])).get(body.alert_id)
    if existing is not None and existing.status == "running":
        raise HTTPException(
            status_code=409,
            detail={
                "reason": "hunt_in_progress",
                "running_inv_id": existing.id,
                "hint": (
                    "a hunt is already running for this alert — open it or cancel "
                    "it before starting a new one"
                ),
            },
        )
    inv_id = await hunt_manager.get_manager(request.app.state).start(
        request.app.state, alert_id=body.alert_id, started_by=started_by
    )
    if inv_id is None:
        raise HTTPException(status_code=503, detail={"reason": "could_not_start"})
    return {"investigation_id": inv_id}


@router.post("/investigations/{inv_id}/cancel")
async def cancel_hunt(inv_id: str, request: Request) -> dict[str, bool]:
    """Cancel an in-flight hunt for an investigation.

    200 ``{"cancelled": true}`` if a running background task was stopped (the
    run lands as ``cancelled``); 404 if there is no in-flight hunt to cancel
    (it already finished, errored, or completed).
    """
    cancelled = hunt_manager.get_manager(request.app.state).cancel(inv_id)
    if not cancelled:
        raise HTTPException(
            status_code=404,
            detail={
                "reason": "not_running",
                "hint": "no in-flight hunt to cancel — it already finished",
            },
        )
    return {"cancelled": True}


@router.delete("/investigations/{inv_id}", dependencies=[Depends(require_admin_api)])
async def delete_investigation(inv_id: str, request: Request) -> dict[str, bool]:
    """Delete an investigation and its events + chat messages (admin only).

    For clearing broken/orphaned runs. Refuses to delete a still-``running``
    investigation (409) — cancel it first — so its background worker can't write
    rows back after the delete.
    """
    async with request.app.state.db_sessionmaker() as db:
        inv = await db.get(Investigation, inv_id)
        if inv is None:
            raise HTTPException(
                status_code=404, detail={"reason": "not_found", "hint": "investigation not found"}
            )
        if inv.status == "running":
            raise HTTPException(
                status_code=409,
                detail={
                    "reason": "still_running",
                    "hint": "cancel the running hunt before deleting it",
                },
            )
        await inv_svc.delete(db, inv_id)
    return {"deleted": True}


_REHUNT_CAP = 50


class RehuntIn(BaseModel):
    inv_ids: list[str]


class RehuntResultOut(BaseModel):
    started: list[dict[str, str]]  # [{invId, newInvId, alertEsId}]
    skipped: list[dict[str, str]]  # [{invId, reason}]


@router.post("/investigations/rehunt", response_model=RehuntResultOut)
async def bulk_rehunt(request: Request, body: RehuntIn) -> RehuntResultOut:
    """Re-launch a fresh investigation for each of the supplied investigation ids.

    Deduplicates the input list and caps at ``_REHUNT_CAP`` entries.  Entries
    beyond the cap are skipped with reason ``"cap"``.  Unknown ids are skipped
    with ``"not_found"``; ids whose investigation has no ``alert_es_id`` are
    skipped with ``"no_alert"``.  Successful entries receive a new investigation
    id via the same path as ``POST /hunt``.
    """
    started_by = await identify_caller(request)
    # Deduplicate while preserving order.
    seen: set[str] = set()
    unique_ids: list[str] = []
    for inv_id in body.inv_ids:
        if inv_id not in seen:
            seen.add(inv_id)
            unique_ids.append(inv_id)

    started: list[dict[str, str]] = []
    skipped: list[dict[str, str]] = []

    for i, inv_id in enumerate(unique_ids):
        if i >= _REHUNT_CAP:
            skipped.append({"invId": inv_id, "reason": "cap"})
            continue

        async with request.app.state.db_sessionmaker() as db:
            inv = await db.get(Investigation, inv_id)

        if inv is None:
            skipped.append({"invId": inv_id, "reason": "not_found"})
            continue

        if not inv.alert_es_id:
            skipped.append({"invId": inv_id, "reason": "no_alert"})
            continue

        new_inv_id = await hunt_manager.get_manager(request.app.state).start(
            request.app.state, alert_id=inv.alert_es_id, started_by=started_by
        )
        if new_inv_id is None:
            skipped.append({"invId": inv_id, "reason": "could_not_start"})
            continue

        started.append({"invId": inv_id, "newInvId": new_inv_id, "alertEsId": inv.alert_es_id})

    return RehuntResultOut(started=started, skipped=skipped)


class ChatThreadOut(BaseModel):
    messages: list[ChatMessageOut]
    pending: bool


def _chat_msg_out(m: Any) -> ChatMessageOut:
    meta = (m.meta or {}) if isinstance(m.meta, dict) else {}
    tools = ", ".join(meta.get("tools", [])) if meta.get("tools") else None
    is_prop = meta.get("kind") == "verdict_proposal"
    return ChatMessageOut(
        role=m.role,
        text=m.content,
        tools=tools,
        messageId=m.id if is_prop else None,
        kind=meta.get("kind") if is_prop else None,
        validation=meta.get("validation") if is_prop else None,
        objection=meta.get("objection") if is_prop else None,
        token=meta.get("token") if (is_prop and meta.get("validation") == "pass") else None,
        applied=bool(meta.get("applied")) if is_prop else None,
        proposal=meta.get("proposal") if is_prop else None,
    )


def _thread(msgs: list[Any]) -> ChatThreadOut:
    return ChatThreadOut(
        messages=[_chat_msg_out(m) for m in msgs],
        pending=any(m.status == "pending" for m in msgs),
    )


@router.get("/investigations/{inv_id}/chat", response_model=ChatThreadOut)
async def get_chat(request: Request, inv_id: str) -> ChatThreadOut:
    """Poll target — the chat thread, with a pending flag while the assistant works."""
    async with request.app.state.db_sessionmaker() as db:
        msgs = await chat_svc.list_messages(db, inv_id)
    return _thread(msgs)


class ChatIn(BaseModel):
    message: str


@router.post("/investigations/{inv_id}/chat", response_model=ChatThreadOut)
async def post_chat(request: Request, inv_id: str, body: ChatIn) -> ChatThreadOut:
    """Ask a follow-up. Writes the user turn + a pending assistant turn, spawns the
    background chat task, and returns the thread (poll GET .../chat until !pending)."""
    text = body.message.strip()
    if not text:
        raise HTTPException(status_code=400, detail={"reason": "empty_message"})
    async with request.app.state.db_sessionmaker() as db:
        inv = await db.get(Investigation, inv_id)
        if inv is None:
            raise HTTPException(status_code=404, detail={"reason": "not_found"})
        if inv.status == "running":
            raise HTTPException(status_code=409, detail={"reason": "still_running"})
        await chat_svc.add_user_message(db, inv_id, text)
        pending = await chat_svc.create_pending_assistant(db, inv_id)
        msgs = await chat_svc.list_messages(db, inv_id)
    chat_manager.get_manager(request.app.state).start(
        request.app.state, inv_id=inv_id, assistant_msg_id=pending.id
    )
    return _thread(msgs)


class ApproveIn(BaseModel):
    token: str
    approved: bool
    reason: str | None = None


@router.post("/approve")
async def approve(request: Request, body: ApproveIn) -> dict[str, Any]:
    """Apply an analyst decision to a pending write-tool approval."""
    result = await apply_approval(
        gate=request.app.state.gate,
        auth=request.app.state.auth,
        settings=request.app.state.settings,
        token=body.token,
        approved=body.approved,
        reason=body.reason,
        audit=request.app.state.audit,
        user=await identify_caller(request),
    )
    return result.model_dump()


# ── Advisory action execution ──────────────────────────────────────────────
# Synth-first investigations recommend write actions in the report rather than
# pausing the agent on an approval gate, so the analyst executes them on demand
# from the report. These run through the *same* execute_write_tool path as the
# gate, restricted to the three write tools, with the alert id defaulted from
# the investigation when the model left it off.


class ExecuteActionResult(BaseModel):
    status: str  # "executed" | "error"
    title: str
    detail: str = ""
    error: str | None = None


def _action_detail(tool_name: str, result: Any) -> str:
    """One-line, analyst-facing confirmation of what the write tool did."""
    if not isinstance(result, dict):
        return ""
    if tool_name == "ack_alert":
        return "Alert acknowledged in Security Onion."
    if tool_name == "escalate_to_case":
        case_id = result.get("id") or result.get("caseId") or result.get("case_id") or ""
        return f"Case created: {case_id}" if case_id else "Case created in Security Onion."
    if tool_name == "add_case_comment":
        case_id = result.get("case_id") or ""
        return f"Comment added to case {case_id}." if case_id else "Comment added to case."
    return ""


@router.post(
    "/investigations/{inv_id}/actions/{index}/execute",
    response_model=ExecuteActionResult,
)
async def execute_action(request: Request, inv_id: str, index: int) -> ExecuteActionResult:
    """Execute one report-recommended write action against Security Onion.

    ``index`` is the position in ``report.recommended_actions`` (the SPA's
    advisory action cards are built in that order). Token-gated approvals use
    ``/approve`` instead; this path is for the advisory recommendations.
    """
    async with request.app.state.db_sessionmaker() as db:
        inv = await db.get(Investigation, inv_id)
        if inv is None:
            by_alert = await inv_svc.latest_for_alerts(db, [inv_id])
            inv = by_alert.get(inv_id)
        if inv is None:
            raise HTTPException(status_code=404, detail={"reason": "not_found"})
        report = inv.report or {}
        alert_es_id = inv.alert_es_id

    recs = report.get("recommended_actions") or []
    if index < 0 or index >= len(recs):
        raise HTTPException(status_code=404, detail={"reason": "no_such_action"})

    rec = recs[index]
    tool_name = rec.get("tool_name", "")
    title = _ACTION_TITLE.get(tool_name, tool_name or "Action")
    if tool_name not in WRITE_TOOLS:
        raise HTTPException(
            status_code=400,
            detail={"reason": "not_executable", "tool": tool_name},
        )

    tool_args = dict(rec.get("tool_args") or {})
    # The model usually fills alert_id, but default it from the investigation's
    # own alert when missing so an ack/escalate never silently targets nothing.
    if tool_name in ("ack_alert", "escalate_to_case") and not tool_args.get("alert_id"):
        if not alert_es_id:
            raise HTTPException(
                status_code=400,
                detail={"reason": "missing_alert_id", "tool": tool_name},
            )
        tool_args["alert_id"] = alert_es_id

    result, error = await execute_write_tool(
        tool_name,
        tool_args,
        auth=request.app.state.auth,
        settings=request.app.state.settings,
        audit=request.app.state.audit,
        session_id=f"action:{inv_id}",
        user=await identify_caller(request),
    )
    if error is not None:
        return ExecuteActionResult(status="error", title=title, error=error)
    return ExecuteActionResult(
        status="executed", title=title, detail=_action_detail(tool_name, result)
    )


# ── Chat verdict resolution ────────────────────────────────────────────────


class ResolveIn(BaseModel):
    message_id: int
    token: str


@router.post("/investigations/{inv_id}/resolve")
async def resolve_investigation(request: Request, inv_id: str, body: ResolveIn) -> dict[str, Any]:
    """Apply a validated chat verdict proposal. Token + message gated, idempotent."""
    # Not owner-scoped: any authenticated caller may apply a proposal, consistent
    # with /approve and the action-execute route. The actor is recorded for audit.
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
        raise HTTPException(
            status_code=400,
            detail={"reason": "invalid_verdict", "valid": sorted(_VALID_VERDICTS)},
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
                    "hint": "Wait for the investigation to complete before overriding.",
                },
            )
        updated = await inv_svc.resolve(
            db,
            inv_id,
            verdict=body.verdict,
            confidence=body.confidence if body.confidence is not None else 1.0,
            rationale=body.rationale,
            recommended_actions=None,
            resolved_by=resolved_by,
            resolved_via="manual",
            source_message_id=None,
        )
        if updated is None:
            raise HTTPException(status_code=404, detail={"reason": "not_found"})
    return {"ok": True, "verdict": body.verdict, "confidence": updated.confidence}


# ── Config mutations (admin) ───────────────────────────────────────────────


class SettingIn(BaseModel):
    key: str
    value: str  # stringified; coerced to the spec's declared type server-side


@router.post("/config/setting", dependencies=[Depends(require_admin_api)])
async def set_setting(request: Request, body: SettingIn) -> dict[str, Any]:
    """Persist + (if hot) hot-apply one whitelisted, non-Danger setting.

    Danger-Zone (connection/secret) settings are deliberately NOT editable here —
    they use the typed-confirm + Fernet path on POST /api/v1/config/danger/setting.
    """
    settings = request.app.state.settings
    if not cfg_svc.is_editable(body.key):
        raise HTTPException(status_code=400, detail={"reason": "unknown_setting"})
    spec = cfg_svc.WHITELIST_BY_KEY[body.key]
    if spec.danger:
        raise HTTPException(
            status_code=400,
            detail={"reason": "danger_zone", "hint": "use POST /api/v1/config/danger/setting"},
        )
    if spec.secret:
        # Secrets never go through the plaintext (secret_box=None) path — that
        # would raise deep in set_override (500). Route them to the dedicated
        # write-only endpoint instead.
        raise HTTPException(
            status_code=400,
            detail={"reason": "secret_setting", "hint": "use POST /api/v1/config/api-keys"},
        )
    try:
        typed = cfg_svc.coerce(body.key, body.value)
    except ValueError as exc:
        raise HTTPException(
            status_code=400, detail={"reason": "invalid_value", "hint": str(exc)}
        ) from exc
    user = await current_user(request)
    async with request.app.state.db_sessionmaker() as db:
        await cfg_svc.set_override(
            db, body.key, typed, updated_by=user.id if user else None, secret_box=None
        )
    restart_required = not spec.hot
    if spec.hot:
        cfg_svc.apply_to_settings(settings, {body.key: typed}, secret_box=None)
    return {"ok": True, "restart_required": restart_required}


class TokenCreateIn(BaseModel):
    # Charset-restricted: the token name surfaces in the alerts-grid owner field
    # (owner = "token:<name>"), so keep it to a safe, non-injectable set.
    name: str = Field(min_length=1, max_length=64, pattern=r"^[\w .\-]+$")


@router.post("/config/tokens", dependencies=[Depends(require_admin_api)])
async def create_token(request: Request, body: TokenCreateIn) -> dict[str, str]:
    """Mint an API token — the raw ``scai_…`` value is returned ONCE.

    Requires a real authenticated session user as the creator. ``created_by`` is
    a non-null FK to ``users.id``; we refuse rather than persist a token attributed
    to user 0 / null (which would happen for a bearer-token caller or a dev session
    that passed the auth gate without a resolvable session user).
    """
    name = body.name.strip() or "token"
    user = await current_user(request)
    if user is None:
        raise HTTPException(
            status_code=403,
            detail={
                "reason": "no_session_user",
                "hint": (
                    "Minting an API token requires an authenticated admin session; "
                    "log in at /app/login (bearer-token callers cannot mint tokens)."
                ),
            },
        )
    async with request.app.state.db_sessionmaker() as db:
        raw = await auth_svc.create_api_token(db, name, user.id)
    return {"token": raw}


@router.post("/config/tokens/{token_id}/revoke", dependencies=[Depends(require_admin_api)])
async def revoke_token(request: Request, token_id: int) -> dict[str, bool]:
    async with request.app.state.db_sessionmaker() as db:
        await auth_svc.revoke_api_token(db, token_id)
    return {"ok": True}


@router.get(
    "/config/danger",
    response_model=list[DangerSettingOut],
    dependencies=[Depends(require_admin_api)],
    tags=["config"],
)
async def api_get_danger_settings(
    request: Request,
    settings: Settings = Depends(get_settings_dep),
) -> list[DangerSettingOut]:
    """List all danger-zone settings. Secret values are NEVER returned — only isSet status."""
    # Fetch all DB override keys in one query to avoid N+1.
    async with request.app.state.db_sessionmaker() as db:
        db_row_keys: set[str] = set(
            (
                await db.scalars(
                    select(ConfigOverride.key).where(
                        ConfigOverride.key.in_(
                            [spec.key for spec in cfg_svc.WHITELIST_BY_KEY.values() if spec.danger]
                        )
                    )
                )
            ).all()
        )

    rows: list[DangerSettingOut] = []
    for spec in cfg_svc.WHITELIST_BY_KEY.values():
        if not spec.danger:
            continue

        # Determine source and isSet: DB takes precedence over env.
        if spec.key in db_row_keys:
            source = "db"
            is_set = True
        else:
            # Check the live Settings attribute (populated from env / .env at startup).
            attr_val = getattr(settings, spec.attr, None)
            if attr_val is None:
                source = "unset"
                is_set = False
            else:
                # SecretStr fields must be unwrapped to check for emptiness.
                raw = (
                    attr_val.get_secret_value()
                    if isinstance(attr_val, SecretStr)
                    else str(attr_val)
                )
                if raw.strip():
                    source = "env"
                    is_set = True
                else:
                    source = "unset"
                    is_set = False

        # Map internal SettingType to the frontend type label.
        if spec.secret:
            field_type = "secret"
        elif spec.type == "bool":
            field_type = "bool"
        elif spec.type == "csv":
            field_type = "csv"
        else:
            field_type = "text"

        rows.append(
            DangerSettingOut(
                key=spec.key,
                label=spec.label,
                type=field_type,
                isSet=is_set,
                source=source,
                hot=spec.hot,
            )
        )
    return rows


@router.post(
    "/config/danger/setting",
    dependencies=[Depends(require_admin_api)],
    tags=["config"],
)
async def api_save_danger_setting(
    body: SaveDangerIn,
    request: Request,
    settings: Settings = Depends(get_settings_dep),
) -> dict[str, object]:
    """Save a danger-zone setting. Requires typed confirmation (confirm must equal key).

    Secret-typed settings are Fernet-encrypted before DB storage.
    Never returns the plaintext value. A hot=True danger spec (PCAP SSH, the
    crawl4ai token, internal_cidrs — all read fresh per tool-call) is applied
    live; the SO/ES/LiteLLM connection settings feed startup clients and still
    need a restart.
    """
    # 1. Typed confirmation guard
    if body.confirm.strip() != body.key:
        raise HTTPException(
            status_code=400,
            detail={"reason": "confirm_mismatch", "hint": "confirm must equal the setting key"},
        )

    # 2. Validate key is a known danger spec
    spec = cfg_svc.WHITELIST_BY_KEY.get(body.key)
    if spec is None or not spec.danger:
        raise HTTPException(
            status_code=400,
            detail={"reason": "unknown_danger_key", "hint": "key is not a known danger setting"},
        )

    # 3. Coerce the string value to the spec's declared type
    try:
        typed = cfg_svc.coerce(body.key, body.value)
    except ValueError as exc:
        raise HTTPException(
            status_code=400, detail={"reason": "invalid_value", "hint": str(exc)}
        ) from exc

    # 4. Determine actor for audit trail (id is int | None)
    user = await current_user(request)
    updated_by: int | None = user.id if user else None

    # 5. Persist — set_override Fernet-encrypts secret-typed values when secret_box is set.
    #    A secret-typed key with no CONFIG_SECRET_KEY makes set_override raise
    #    ValueError; surface that as a 400 (operator must set the key) rather than
    #    an uncaught 500. No plaintext is written on this path.
    secret_box = request.app.state.secret_box
    try:
        async with request.app.state.db_sessionmaker() as db:
            await cfg_svc.set_override(
                db,
                body.key,
                typed,
                updated_by=updated_by,
                secret_box=secret_box if spec.secret else None,
            )
    except ValueError as exc:
        raise HTTPException(
            status_code=400,
            detail={
                "reason": "no_config_secret_key",
                "hint": "Set CONFIG_SECRET_KEY to edit secret values via the UI.",
            },
        ) from exc

    # Hot specs are read fresh per tool-call → apply live via setattr on the
    # Settings singleton (validate_assignment coerces str→SecretStr, csv→typed).
    # restart_required reflects whether it actually applied (a non-hot spec, or a
    # value that fails live validation, still persists and applies on restart).
    applied_live = False
    if spec.hot:
        try:
            setattr(settings, spec.attr, typed)
            applied_live = True
        except (ValueError, TypeError, ValidationError):
            applied_live = False

    return {"ok": True, "restart_required": not applied_live}


# ── API keys (hot, write-only enrichment provider secrets) ────────────────────
# Distinct from the Danger-Zone secrets (SO/ES/LiteLLM, restart-required): these
# enrichment keys are read per tool-call, so a save hot-applies live (no restart)
# and no typed confirm is required. Values are Fernet-encrypted at rest and never
# returned to the client.


class ApiKeyOut(BaseModel):
    key: str
    label: str
    help: str
    isSet: bool
    source: str  # "db" | "env" | "unset"


class SaveApiKeyIn(BaseModel):
    key: str
    value: str


@router.get(
    "/config/api-keys",
    response_model=list[ApiKeyOut],
    dependencies=[Depends(require_admin_api)],
    tags=["config"],
)
async def api_get_api_keys(
    request: Request,
    settings: Settings = Depends(get_settings_dep),
) -> list[ApiKeyOut]:
    """List the enrichment API-key fields. Values are NEVER returned — only isSet."""
    specs = cfg_svc.api_key_specs()
    async with request.app.state.db_sessionmaker() as db:
        db_keys: set[str] = set(
            (
                await db.scalars(
                    select(ConfigOverride.key).where(ConfigOverride.key.in_([s.key for s in specs]))
                )
            ).all()
        )
    out: list[ApiKeyOut] = []
    for spec in specs:
        if spec.key in db_keys:
            source, is_set = "db", True
        else:
            attr_val = getattr(settings, spec.attr, None)
            raw = (
                attr_val.get_secret_value()
                if isinstance(attr_val, SecretStr)
                else ("" if attr_val is None else str(attr_val))
            )
            source, is_set = ("env", True) if raw.strip() else ("unset", False)
        out.append(
            ApiKeyOut(key=spec.key, label=spec.label, help=spec.help, isSet=is_set, source=source)
        )
    return out


@router.post(
    "/config/api-keys",
    dependencies=[Depends(require_admin_api)],
    tags=["config"],
)
async def api_save_api_key(
    body: SaveApiKeyIn,
    request: Request,
    settings: Settings = Depends(get_settings_dep),
) -> dict[str, object]:
    """Save an enrichment API key (Fernet-encrypted, write-only) and hot-apply it."""
    spec = cfg_svc.WHITELIST_BY_KEY.get(body.key)
    if spec is None or not spec.secret or spec.danger:
        raise HTTPException(
            status_code=400,
            detail={"reason": "unknown_api_key", "hint": "key is not a known API-key setting"},
        )
    value = body.value.strip()
    if not value:
        raise HTTPException(
            status_code=400,
            detail={"reason": "empty_value", "hint": "send a non-empty value, or DELETE to clear"},
        )
    user = await current_user(request)
    updated_by: int | None = user.id if user else None
    secret_box = request.app.state.secret_box
    try:
        async with request.app.state.db_sessionmaker() as db:
            await cfg_svc.set_override(
                db, body.key, value, updated_by=updated_by, secret_box=secret_box
            )
    except ValueError as exc:
        raise HTTPException(
            status_code=400,
            detail={
                "reason": "no_config_secret_key",
                "hint": "Set CONFIG_SECRET_KEY to store API keys via the UI.",
            },
        ) from exc
    # Hot-apply: enrichment keys are read fresh per tool-call. setattr the
    # plaintext onto the live Settings singleton (validate_assignment coerces
    # str → SecretStr). NOT apply_to_settings — that decrypts a stored token.
    setattr(settings, spec.attr, value)
    return {"ok": True, "isSet": True}


@router.delete(
    "/config/api-keys/{key}",
    dependencies=[Depends(require_admin_api)],
    tags=["config"],
)
async def api_clear_api_key(
    key: str,
    request: Request,
    settings: Settings = Depends(get_settings_dep),
) -> dict[str, object]:
    """Clear an enrichment API key: drop the DB override and unset the live value."""
    spec = cfg_svc.WHITELIST_BY_KEY.get(key)
    if spec is None or not spec.secret or spec.danger:
        raise HTTPException(
            status_code=400,
            detail={"reason": "unknown_api_key", "hint": "key is not a known API-key setting"},
        )
    async with request.app.state.db_sessionmaker() as db:
        await cfg_svc.delete_override(db, key)
    # Hot-clear the live value (reverts to None until a restart re-applies env).
    setattr(settings, spec.attr, None)
    return {"ok": True, "isSet": False}


class AgentToolsOut(BaseModel):
    tools: list[agent_tools_svc.AgentToolOut]


@router.get(
    "/config/agent-tools",
    response_model=AgentToolsOut,
    dependencies=[Depends(require_admin_api)],
    tags=["config"],
)
async def api_get_agent_tools(
    settings: Settings = Depends(get_settings_dep),
) -> AgentToolsOut:
    """List every tool available to the agent, with its description + dependencies."""
    return AgentToolsOut(tools=agent_tools_svc.collect_agent_tools(settings))


_DANGER_TEST_TARGETS: frozenset[str] = frozenset({"es", "llm"})


@router.post(
    "/config/danger/test/{target}",
    response_model=ConnTestOut,
    dependencies=[Depends(require_admin_api)],
    tags=["config"],
)
async def api_danger_test_connection(
    target: str,
    request: Request,
    settings: Settings = Depends(get_settings_dep),
) -> ConnTestOut:
    """Run a connectivity probe for target ∈ {es, llm}.
    Returns {ok, detail}. Detail is secret-free — probes.py scrubs credentials internally.
    """
    if target not in _DANGER_TEST_TARGETS:
        valid = sorted(_DANGER_TEST_TARGETS)
        raise HTTPException(
            status_code=400,
            detail={"reason": "unknown_target", "hint": f"target must be one of {valid}"},
        )

    if target == "es":
        result = await probes.probe_es(request.app.state.elastic)
    else:
        result = await probes.probe_llm(settings)

    return ConnTestOut(ok=result["ok"], detail=result["detail"])


# ── Current-user endpoints ────────────────────────────────────────────────


class MeOut(BaseModel):
    username: str
    role: str
    status: str


class SetStatusIn(BaseModel):
    status: str = Field(default="", max_length=120)


_DEV_ME = MeOut(username="analyst", role="admin", status="")


@router.get("/me", response_model=MeOut)
async def get_me(request: Request) -> MeOut:
    """Return the current user's username, role, and status.

    When ``api_auth_required`` is False (dev / lab default) and there is no
    active session, return a sensible dev fallback so the SPA always has a
    user to render.  When auth IS required and there is no session, the
    ``require_api_auth`` dependency already rejected the request with 401
    before this handler runs.
    """
    user = await current_user(request)
    if user is None:
        return _DEV_ME
    return MeOut(username=user.username, role=user.role, status=user.status)


@router.post("/me/status")
async def set_my_status(request: Request, body: SetStatusIn) -> dict[str, str | bool]:
    """Update the current user's status string (trim + cap at 64 chars).

    In dev mode with no session the request is a no-op that echoes back the
    (sanitised) status — nothing is persisted.
    """
    trimmed = body.status.strip()[:64]
    user = await current_user(request)
    if user is None:
        # Dev / no-auth mode: nothing to persist, just echo back.
        return {"ok": True, "status": trimmed}
    async with request.app.state.db_sessionmaker() as db:
        await auth_svc.set_user_status(db, user.id, trimmed)
    return {"ok": True, "status": trimmed}


# ── User management (admin) ────────────────────────────────────────────────


class UserOut(BaseModel):
    id: int
    username: str
    role: str
    disabled: bool
    status: str
    lastLoginAt: str | None


class UsersListOut(BaseModel):
    users: list[UserOut]


class CreateUserIn(BaseModel):
    username: str = Field(min_length=1, max_length=64, pattern=r"^[\w.\-@]+$")
    password: str = Field(min_length=1, max_length=1024)
    role: str


class SetRoleIn(BaseModel):
    role: str


@router.get("/config/users", response_model=UsersListOut, dependencies=[Depends(require_admin_api)])
async def list_users_endpoint(request: Request) -> UsersListOut:
    async with request.app.state.db_sessionmaker() as db:
        users = await auth_svc.list_users(db)
    return UsersListOut(
        users=[
            UserOut(
                id=u.id,
                username=u.username,
                role=u.role,
                disabled=u.disabled,
                status=u.status,
                lastLoginAt=u.last_login_at.isoformat() if u.last_login_at is not None else None,
            )
            for u in users
        ]
    )


@router.post("/config/users", dependencies=[Depends(require_admin_api)])
async def create_user_endpoint(request: Request, body: CreateUserIn) -> dict[str, bool]:
    username = body.username.strip()
    if not username:
        raise HTTPException(
            status_code=400,
            detail={"reason": "username_required", "hint": "Username must not be empty."},
        )
    if len(body.password) < 8:
        raise HTTPException(
            status_code=400,
            detail={
                "reason": "password_too_short",
                "hint": "Password must be at least 8 characters.",
            },
        )
    if body.role not in auth_svc.VALID_ROLES:
        raise HTTPException(
            status_code=400,
            detail={"reason": "invalid_role", "hint": "Role must be admin or analyst."},
        )
    async with request.app.state.db_sessionmaker() as db:
        existing = await auth_svc.list_users(db)
        if any(u.username == username for u in existing):
            raise HTTPException(
                status_code=400,
                detail={
                    "reason": "username_taken",
                    "hint": f"Username {username!r} is already taken.",
                },
            )
        try:
            await auth_svc.create_user(db, username, body.password, role=body.role)
        except IntegrityError as exc:
            raise HTTPException(
                status_code=400,
                detail={
                    "reason": "username_taken",
                    "hint": f"Username {username!r} is already taken.",
                },
            ) from exc
    return {"ok": True}


@router.post(
    "/config/users/{user_id}/toggle-disabled",
    dependencies=[Depends(require_admin_api)],
)
async def toggle_user_disabled(request: Request, user_id: int) -> dict[str, bool | int]:
    # Resolve caller for self-disable guard: session user OR API-token bearer
    caller = await current_user(request)
    if caller is None and request.app.state.settings.api_auth_required:
        # Bearer-token caller: resolve user from token so self-disable is blocked
        authz = request.headers.get("authorization", "")
        if authz.lower().startswith("bearer "):
            raw_token = authz[7:].strip()
            async with request.app.state.db_sessionmaker() as _db:
                api_tok = await auth_svc.check_api_token(_db, raw_token)
            if api_tok is not None:
                async with request.app.state.db_sessionmaker() as _db:
                    caller = await auth_svc.get_user_by_id(_db, api_tok.created_by)
    if caller is not None and caller.id == user_id:
        raise HTTPException(
            status_code=400,
            detail={
                "reason": "cannot_disable_self",
                "hint": "You cannot disable your own account.",
            },
        )
    async with request.app.state.db_sessionmaker() as db:
        target = await auth_svc.get_user_by_id(db, user_id)
        if target is None:
            raise HTTPException(
                status_code=400,
                detail={"reason": "user_not_found", "hint": f"No user with id {user_id}."},
            )
        will_disable = not target.disabled
        if will_disable and target.role == "admin":
            count = await auth_svc.count_enabled_admins(db)
            if count <= 1:
                raise HTTPException(
                    status_code=400,
                    detail={
                        "reason": "last_admin",
                        "hint": "Cannot disable the last enabled admin.",
                    },
                )
        await auth_svc.set_user_disabled(db, user_id, will_disable)
    return {"ok": True, "disabled": will_disable}


@router.post(
    "/config/users/{user_id}/reset-password",
    dependencies=[Depends(require_admin_api)],
)
async def reset_user_password_endpoint(request: Request, user_id: int) -> dict[str, str | bool]:
    async with request.app.state.db_sessionmaker() as db:
        target = await auth_svc.get_user_by_id(db, user_id)
        if target is None:
            raise HTTPException(
                status_code=400,
                detail={"reason": "user_not_found", "hint": f"No user with id {user_id}."},
            )
        new_pw = secrets.token_urlsafe(12)
        await auth_svc.reset_user_password(db, user_id, new_pw)
    return {"ok": True, "password": new_pw}


@router.post(
    "/config/users/{user_id}/set-role",
    dependencies=[Depends(require_admin_api)],
)
async def set_user_role_endpoint(
    request: Request, user_id: int, body: SetRoleIn
) -> dict[str, bool]:
    if body.role not in auth_svc.VALID_ROLES:
        raise HTTPException(
            status_code=400,
            detail={"reason": "invalid_role", "hint": "Role must be admin or analyst."},
        )
    async with request.app.state.db_sessionmaker() as db:
        target = await auth_svc.get_user_by_id(db, user_id)
        if target is None:
            raise HTTPException(
                status_code=400,
                detail={"reason": "user_not_found", "hint": f"No user with id {user_id}."},
            )
        if target.role == "admin" and body.role != "admin" and not target.disabled:
            count = await auth_svc.count_enabled_admins(db)
            if count <= 1:
                raise HTTPException(
                    status_code=400,
                    detail={"reason": "last_admin", "hint": "Cannot demote the last admin."},
                )
        await auth_svc.set_user_role(db, user_id, body.role)
    return {"ok": True}


# ── Auto-triage (bulk) ─────────────────────────────────────────────────────


class AutoTriageStatusOut(BaseModel):
    active: bool
    total: int
    hunted: int
    skipped: int
    failed: int
    finished_at: str | None = None
    severities: list[str] = []
    note: str | None = None
    current: str | None = None
    tool_calls: int = 0


def _at_status(status: Any, note: str | None = None) -> AutoTriageStatusOut:
    return AutoTriageStatusOut(
        active=status.active,
        total=status.total,
        hunted=status.hunted,
        skipped=status.skipped,
        failed=status.failed,
        finished_at=status.finished_at,
        severities=list(status.severities),
        note=note,
        current=status.current,
        tool_calls=status.tool_calls,
    )


class AutoTriageIn(BaseModel):
    range: str = aq.DEFAULT_RANGE
    q: str | None = None
    severities: list[str] = []
    # Explicit operator selection (alert ES ids). When present, auto-triage
    # honours the selection — bypassing severity/range planning and the
    # max-targets cap — and only skips ids that already carry a verdict.
    alert_ids: list[str] = []


@router.post("/auto-triage", response_model=AutoTriageStatusOut)
async def start_auto_triage(request: Request, body: AutoTriageIn) -> AutoTriageStatusOut:
    """Plan + launch a background auto-triage batch (single-flight). Poll
    GET /auto-triage for progress. With ``alert_ids`` it triages exactly that
    selection (already-verdicted ids skipped); otherwise it sweeps the
    critical+high detections in range."""
    state = request.app.state
    status = at.get_status(state)
    if status.active:
        return _at_status(status, note="already running")

    selected = [a for a in body.alert_ids if a]
    # Derive the config-default severity band: everything at or above the floor.
    _ladder = list(aq.SEVERITIES)  # ("critical", "high", "medium", "low")
    _settings = state.settings
    _floor = getattr(_settings, "auto_triage_min_severity", "high")
    _idx = _ladder.index(_floor) if _floor in _ladder else _ladder.index("high")
    _config_band: tuple[str, ...] = tuple(_ladder[: _idx + 1])
    chosen: tuple[str, ...] = _config_band
    status.active = True  # claim the slot before any await
    try:
        if selected:
            targets, skipped = await at.plan_targets_for_ids(state, alert_ids=selected)
        else:
            # Explicit severities from the caller take precedence over the config floor.
            chosen = tuple(s for s in body.severities if s in aq.SEVERITIES) or _config_band
            time_range = body.range if body.range in aq.TIME_RANGES else aq.DEFAULT_RANGE
            oql = (body.q or "").strip() or None
            targets, skipped = await at.plan_targets(
                state, time_range=time_range, oql=oql, severities=chosen
            )
    except Exception:
        status.active = False
        raise HTTPException(status_code=500, detail={"reason": "planning_failed"}) from None

    if not targets:
        status.reset(active=False, total=0, skipped=skipped, severities=chosen)
        status.finished_at = datetime.now(UTC).isoformat()
        if selected:
            empty_note = (
                f"all {skipped} selected already triaged" if skipped else "nothing to triage"
            )
        else:
            empty_note = "nothing to hunt"
        return _at_status(status, note=empty_note)

    status.reset(active=True, total=len(targets), skipped=skipped, severities=chosen)
    started_by = f"auto-triage:{await identify_caller(request)}"
    status._task = asyncio.create_task(
        at.run_auto_triage(state, targets=targets, started_by=started_by)
    )
    note: str | None = None
    if selected:
        note = f"triaging {len(targets)} selected"
        if skipped:
            note += f" ({skipped} already triaged)"
    return _at_status(status, note=note)


@router.get("/auto-triage", response_model=AutoTriageStatusOut)
async def auto_triage_status(request: Request) -> AutoTriageStatusOut:
    return _at_status(at.get_status(request.app.state))


@router.post("/auto-triage/stop", response_model=AutoTriageStatusOut)
async def stop_auto_triage(request: Request) -> AutoTriageStatusOut:
    """Request an in-flight auto-triage run to stop after its current target.

    The current investigation is allowed to finish cleanly; no further targets
    are started. Returns the (now winding-down) status; a no-op if idle.
    """
    state = request.app.state
    at.request_stop(state)
    return _at_status(at.get_status(state))


# ── Internal-identifier discovery: scan-now (single-flight) ────────────────────
#
# Learns internal domain suffixes + bare hostnames from ES and upserts them as
# detected internal_identifier rows. Modeled on the auto-triage pattern: a
# background asyncio task with an in-memory status on app.state, single-flight
# (a second POST while a scan runs returns the running status, doesn't start a
# second). Reuses app.state.elastic + app.state.db_sessionmaker.

_DISCOVERY_STATE_ATTR = "_discovery_status"


class _DiscoveryStatus:
    """In-memory status for the discovery scan-now task on app.state."""

    def __init__(self) -> None:
        self.running: bool = False
        self.last_scan: str | None = None
        self.last_summary: dict[str, Any] | None = None
        self._task: asyncio.Task[None] | None = None


def _get_discovery_status(state: Any) -> _DiscoveryStatus:
    if not hasattr(state, _DISCOVERY_STATE_ATTR):
        setattr(state, _DISCOVERY_STATE_ATTR, _DiscoveryStatus())
    return getattr(state, _DISCOVERY_STATE_ATTR)  # type: ignore[no-any-return]


class DiscoveryStatusOut(BaseModel):
    running: bool
    last_scan: str | None = None
    last_summary: dict[str, Any] | None = None
    note: str | None = None


def _discovery_status_out(status: _DiscoveryStatus, note: str | None = None) -> DiscoveryStatusOut:
    return DiscoveryStatusOut(
        running=status.running,
        last_scan=status.last_scan,
        last_summary=status.last_summary,
        note=note,
    )


async def _run_discovery_task(state: Any) -> None:
    """Background worker: run one discovery scan, stash the summary, never raise."""
    from dataclasses import asdict  # noqa: PLC0415 - lazy

    from soc_ai.enrichment.discovery import run_discovery  # noqa: PLC0415 - lazy

    status = _get_discovery_status(state)
    try:
        summary = await run_discovery(state.elastic, state.db_sessionmaker, state.settings)
        status.last_summary = asdict(summary)
    except Exception:
        _LOGGER.exception("discovery: scan-now task failed")
        status.last_summary = {"errors": ["scan failed; see server logs"]}
    finally:
        status.running = False
        status.last_scan = datetime.now(UTC).isoformat()


@router.post(
    "/discovery/scan",
    response_model=DiscoveryStatusOut,
    dependencies=[Depends(require_admin_api)],
)
async def start_discovery_scan(request: Request) -> DiscoveryStatusOut:
    """Launch a background internal-identifier discovery scan (single-flight).

    Poll ``GET /discovery/scan`` for status. A second POST while a scan is in
    flight returns the running status instead of starting a second scan. Returns
    a note when discovery is disabled (nothing is started)."""
    state = request.app.state
    status = _get_discovery_status(state)
    if status.running:
        return _discovery_status_out(status, note="already running")
    if not state.settings.discovery_enabled:
        return _discovery_status_out(status, note="discovery disabled")
    status.running = True  # claim the slot before scheduling
    status._task = asyncio.create_task(_run_discovery_task(state))
    return _discovery_status_out(status, note="started")


@router.get(
    "/discovery/scan",
    response_model=DiscoveryStatusOut,
    dependencies=[Depends(require_admin_api)],
)
async def discovery_scan_status(request: Request) -> DiscoveryStatusOut:
    return _discovery_status_out(_get_discovery_status(request.app.state))


# ── Internal-identifier managed list: REST CRUD ────────────────────────────────
#
# Surfaces the ``internal_identifier`` table to the config console. Each kind
# ('suffix' | 'host' | 'cidr') is presented as a group of MUTABLE DB rows plus
# read-only ALWAYS-ON entries (the env/reserved identifiers from the effective
# set that have no DB row). The always-on entries have no id, so the
# deactivate/delete routes below (which take an id) cannot suppress a
# reserved/env default — that enforces the spec's "deactivating cannot remove an
# env/reserved default (the floor wins)" contract at the API surface.
# Kind-generic: increment 3 adds a 'cidr' group with no rework here.

# Reserved special-use suffixes that the egress sanitizer always re-adds as a
# floor (mirrors ``soc_ai.oracle.sanitize._DEFAULT_SUFFIXES`` and the default
# ``Settings.oracle_internal_suffixes``). Always-on suffixes in this set are
# labeled 'reserved'; operator-configured env identifiers beyond it are 'env'.
_RESERVED_SUFFIXES = (".lan", ".local", ".internal", ".corp")


class InternalIdentifierRowOut(BaseModel):
    """One managed-list entry. Mutable rows carry an ``id``; always-on don't."""

    id: int | None = None
    value: str
    source: str  # 'detected' | 'manual' | 'reserved' | 'env'
    state: str  # 'active' | 'muted'
    evidence: dict[str, Any] | None = None
    mutable: bool


class InternalIdentifierGroupOut(BaseModel):
    kind: str  # 'suffix' | 'host' | 'cidr'
    rows: list[InternalIdentifierRowOut]


class InternalIdentifiersOut(BaseModel):
    groups: list[InternalIdentifierGroupOut]
    last_scan: DiscoveryStatusOut


class InternalIdentifierIn(BaseModel):
    kind: str
    # Domains / hostnames / IPs / CIDRs only — blocks injection payloads while
    # allowing every legitimate identifier shape (the cidr path validates further).
    value: str = Field(min_length=1, max_length=253, pattern=r"^[\w.\-:/]+$")


_IDENTIFIER_KINDS = ("suffix", "host", "cidr")


def _always_on_source(kind: str, value: str) -> str:
    """Classify an always-on (no-DB-row) identifier as 'reserved' or 'env'.

    Only suffixes have a hardcoded reserved floor; for those, a value in
    ``_RESERVED_SUFFIXES`` is 'reserved', anything else is operator-set 'env'.
    Hosts/CIDRs have no reserved defaults, so they're always 'env'.
    """
    if kind == "suffix" and value in _RESERVED_SUFFIXES:
        return "reserved"
    return "env"


@router.get(
    "/internal-identifiers",
    response_model=InternalIdentifiersOut,
    dependencies=[Depends(require_admin_api)],
)
async def list_internal_identifiers(
    request: Request,
    settings: Settings = Depends(get_settings_dep),
) -> InternalIdentifiersOut:
    """Managed internal-identifier list grouped by kind.

    Each group is the mutable DB rows (``list_identifiers``) plus the read-only
    always-on env/reserved entries: the values in the effective set that are NOT
    represented by a DB row. Always-on entries have no id and no active toggle —
    that's why ``.lan`` shows as an always-on row the operator can't deactivate.
    Also returns the discovery ``last_scan`` status (reusing the 2b status object).
    """
    from soc_ai.oracle.identifiers import (  # noqa: PLC0415 - lazy
        effective_internal_identifiers,
    )

    async with request.app.state.db_sessionmaker() as db:
        effective = await effective_internal_identifiers(db, settings)
        effective_by_kind: dict[str, list[str]] = {
            "suffix": list(effective.suffixes),
            "host": list(effective.hosts),
            "cidr": [str(net) for net in effective.cidrs],
        }
        groups: list[InternalIdentifierGroupOut] = []
        for kind in _IDENTIFIER_KINDS:
            db_rows = await ids_store.list_identifiers(db, kind)
            rows: list[InternalIdentifierRowOut] = [
                InternalIdentifierRowOut(
                    id=r.id,
                    value=r.value,
                    source=r.source,
                    state=r.state,
                    evidence=r.evidence,
                    mutable=True,
                )
                for r in db_rows
            ]
            # Always-on = effective values not already present as a DB row. (An
            # active DB row whose value is also an env default appears as its
            # mutable row, not duplicated as always-on.)
            db_values = {r.value for r in db_rows}
            for value in effective_by_kind[kind]:
                if value in db_values:
                    continue
                rows.append(
                    InternalIdentifierRowOut(
                        id=None,
                        value=value,
                        source=_always_on_source(kind, value),
                        state="active",
                        evidence=None,
                        mutable=False,
                    )
                )
            groups.append(InternalIdentifierGroupOut(kind=kind, rows=rows))

    last_scan = _discovery_status_out(_get_discovery_status(request.app.state))
    return InternalIdentifiersOut(groups=groups, last_scan=last_scan)


@router.post(
    "/internal-identifiers",
    response_model=InternalIdentifierRowOut,
    dependencies=[Depends(require_admin_api)],
)
async def add_internal_identifier(
    request: Request, body: InternalIdentifierIn
) -> InternalIdentifierRowOut:
    """Add a manual identifier. Bad kind / invalid value → 400."""
    async with request.app.state.db_sessionmaker() as db:
        try:
            row = await ids_store.add_manual(db, body.kind, body.value)
        except ValueError as exc:
            raise HTTPException(
                status_code=400, detail={"reason": "invalid_identifier", "hint": str(exc)}
            ) from exc
        return InternalIdentifierRowOut(
            id=row.id,
            value=row.value,
            source=row.source,
            state=row.state,
            evidence=row.evidence,
            mutable=True,
        )


async def _set_identifier_state(
    request: Request, ident_id: int, state: str
) -> InternalIdentifierRowOut:
    async with request.app.state.db_sessionmaker() as db:
        row = await ids_store.set_state(db, ident_id, state)
        if row is None:
            raise HTTPException(status_code=404, detail={"reason": "not_found"})
        return InternalIdentifierRowOut(
            id=row.id,
            value=row.value,
            source=row.source,
            state=row.state,
            evidence=row.evidence,
            mutable=True,
        )


@router.post(
    "/internal-identifiers/{ident_id}/deactivate",
    response_model=InternalIdentifierRowOut,
    dependencies=[Depends(require_admin_api)],
)
async def deactivate_internal_identifier(
    request: Request, ident_id: int
) -> InternalIdentifierRowOut:
    return await _set_identifier_state(request, ident_id, "muted")


@router.post(
    "/internal-identifiers/{ident_id}/activate",
    response_model=InternalIdentifierRowOut,
    dependencies=[Depends(require_admin_api)],
)
async def activate_internal_identifier(request: Request, ident_id: int) -> InternalIdentifierRowOut:
    return await _set_identifier_state(request, ident_id, "active")


@router.delete(
    "/internal-identifiers/{ident_id}",
    dependencies=[Depends(require_admin_api)],
)
async def delete_internal_identifier(request: Request, ident_id: int) -> dict[str, Any]:
    """Delete a manual identifier. Refuses a detected row → 409 (deactivate it)."""
    async with request.app.state.db_sessionmaker() as db:
        deleted = await ids_store.delete_manual(db, ident_id)
        if not deleted:
            raise HTTPException(
                status_code=409,
                detail={
                    "reason": "not_deletable",
                    "hint": "Detected identifiers cannot be deleted — deactivate them instead.",
                },
            )
    return {"ok": True}


# ── Upstream health (ES / LLM / PCAP) — drives the live status indicator ───────

_PCAP_PROBE_TTL_S = 300.0  # SSH is heavy; cache the PCAP probe between polls.


class HealthComponentOut(BaseModel):
    ok: bool
    detail: str


class HealthOut(BaseModel):
    es: HealthComponentOut
    llm: HealthComponentOut
    pcap: HealthComponentOut | None = None  # only when pcap_enabled


async def _cached_pcap_probe(state: Any, settings: Settings) -> dict[str, Any]:
    now = time.monotonic()
    cached = getattr(state, "_pcap_probe_cache", None)
    if cached is not None and now - cached[0] < _PCAP_PROBE_TTL_S:
        return cached[1]  # type: ignore[no-any-return]
    result = await probes.probe_pcap(settings)
    state._pcap_probe_cache = (now, result)
    return result


@router.get("/health", response_model=HealthOut)
async def health(
    request: Request,
    settings: Settings = Depends(get_settings_dep),
) -> HealthOut:
    """Live status of the upstreams the UI depends on. ES + LLM are probed each
    call (cheap HTTP); PCAP (heavy SSH) is cached. Secret-free details."""
    es = await probes.probe_es(request.app.state.elastic)
    llm = await probes.probe_llm(settings)
    out = HealthOut(
        es=HealthComponentOut(**es),
        llm=HealthComponentOut(**llm),
    )
    if settings.pcap_enabled:
        out.pcap = HealthComponentOut(**await _cached_pcap_probe(request.app.state, settings))
    return out
