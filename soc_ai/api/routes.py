"""HTTP routes for soc-ai - SSE investigate, alert resolution, health."""

from __future__ import annotations

import asyncio
import logging
import re
from datetime import datetime, timedelta
from typing import Any

from elastic_transport import TransportError
from elasticsearch import ApiError
from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import PlainTextResponse
from sse_starlette.sse import EventSourceResponse

from soc_ai import __version__, metrics
from soc_ai.agent.orchestrator import (
    InvestigationContext,
    investigate,
)
from soc_ai.api.deps import (
    get_elastic,
    get_investigation_ctx,
    get_settings_dep,
)
from soc_ai.api.runner import recorded_run, sse_encode
from soc_ai.api.schemas import (
    FindAlertRequest,
    FindAlertResponse,
    HealthResponse,
    InvestigateRequest,
)
from soc_ai.api.security import identify_caller, require_api_auth, require_csrf_safe
from soc_ai.api.webui.routes_alerts import _es_api_error_http, _grid_unavailable
from soc_ai.api.webui_api import resolve_alert_for_hunt
from soc_ai.config import Settings
from soc_ai.demo.replay import find_replay, replay_recorded_run
from soc_ai.so_client.elastic import ElasticClient
from soc_ai.store import investigations as inv_svc

_LOGGER = logging.getLogger(__name__)

# SO's UI prints timestamps as "2026-05-08 17:04:21.855 -04:00" (space before
# the timezone offset), which Python's datetime.fromisoformat does NOT accept.
# Strip that space so the standard parser works.
_SO_TS_TZ_GAP = re.compile(r"\s+([+-]\d{2}:?\d{2})$")


def _parse_so_timestamp(s: str) -> datetime:
    """Parse SO-formatted or ISO-8601 timestamps tolerantly."""
    norm = s.strip()
    norm = _SO_TS_TZ_GAP.sub(r"\1", norm)
    norm = norm.replace("Z", "+00:00")
    return datetime.fromisoformat(norm)


# require_csrf_safe is enforced router-wide so the legacy mutating routes
# (/investigate, /find-alert) get the same cross-origin cookie-write
# protection as /api/v1. GET routes (/healthz, /metrics) are exempt by method.
router = APIRouter(dependencies=[Depends(require_csrf_safe)])


@router.get("/healthz", response_model=HealthResponse)
async def healthz(
    settings: Settings = Depends(get_settings_dep),
) -> HealthResponse:
    """Liveness + minimal config-snapshot endpoint."""
    return HealthResponse(
        status="ok",
        version=__version__,
        so_auth="connect" if settings.use_connect_api else "kratos",
        misp_configured=settings.misp_url is not None,
    )


@router.get(
    "/metrics",
    response_class=PlainTextResponse,
    dependencies=[Depends(require_api_auth)],
)
async def metrics_endpoint() -> str:
    """Prometheus 0.0.4 plain-text exposition.

    Counters are in-process — Prometheus's pull model handles per-scrape
    rates without any persistence on our side. See ``soc_ai/metrics.py``
    for the metric set + rationale.
    """
    return metrics.render(version=__version__)


@router.post("/investigate", dependencies=[Depends(require_api_auth)])
async def investigate_endpoint(
    req: InvestigateRequest,
    request: Request,
    ctx: InvestigationContext = Depends(get_investigation_ctx),
    elastic: ElasticClient = Depends(get_elastic),
) -> EventSourceResponse:
    """Stream a triage investigation as Server-Sent Events.

    Each SSE message has ``event: {kind}`` and ``data: {json}`` where the
    JSON body is the :class:`StepEvent` payload.

    The stream is teed into the investigations store so every run is
    persisted regardless of caller (web UI, automation / integrations).
    The leading ``investigation_created`` event carries the new row's id.
    """
    started_by = await identify_caller(request)

    # Demo mode (SOC_AI_DEMO): pure playback of this alert's RECORDED run through
    # the same recorder + SSE encoder — no ES resolve, no LLM. A missing recording
    # replays the live pipeline's unknown-alert error stream (see demo/replay.py).
    if ctx.settings.soc_ai_demo:
        replay = find_replay(getattr(request.app.state, "demo_fixtures", None), req.alert_id)

        # Demo is unauthenticated (API_AUTH_REQUIRED=false). Mirror POST
        # /api/v1/hunt's in-flight guard so a visitor can't spawn a second
        # concurrent replay row while one for this alert is still ``running`` —
        # bounding duplicate demo rows to one per recorded alert. (An unrecorded
        # alert creates no row at all; replay.py already hardens that, F37.)
        reuse_inv_id: str | None = None
        if replay is not None:
            async with request.app.state.db_sessionmaker() as db:
                existing = (await inv_svc.latest_for_alerts(db, [req.alert_id])).get(req.alert_id)
                # Reuse ANY completed replay row for this alert — not only when the
                # LATEST row is complete. A client that aborts this inline SSE
                # mid-stream lands an 'error' row that becomes the latest; a
                # latest-based check would then miss the earlier complete row, so
                # each abort would add a row AND force the next post to persist a
                # fresh one (~1 row/request under abort-looping). Querying the
                # completed set directly closes that residual.
                complete = await inv_svc.complete_for_alert(db, req.alert_id)
            if existing is not None and existing.status == "running":
                raise HTTPException(
                    status_code=409,
                    detail={
                        "reason": "investigation_in_progress",
                        "running_inv_id": existing.id,
                        "hint": (
                            "an investigation is already running for this alert — "
                            "open it or wait for it to finish before starting another"
                        ),
                    },
                )
            # A completed replay row exists for this alert — re-stream the recorded
            # events STORELESS against it rather than persisting a fresh row. Bounds
            # demo replay rows to the recorded-alert set, so an anonymous visitor
            # looping /investigate can't grow the table (the hunt-start ephemeral
            # treatment, one route over).
            if complete is not None:
                reuse_inv_id = complete.id

        async def demo_stream() -> Any:
            async for name, data in replay_recorded_run(
                request.app.state,
                alert_id=req.alert_id,
                started_by=started_by,
                replay=replay,
                reuse_inv_id=reuse_inv_id,
            ):
                yield sse_encode(name, data)

        return EventSourceResponse(demo_stream())

    # Resolve the rule name up front so the investigation row is named at creation
    # — a run that dies before its first alert_context event (e.g. an ES prefetch
    # error) must not leave a nameless "Alert <id>…" row. Best-effort: a resolution
    # failure must never block the actual investigation, so fall back to None and
    # let the recorder backfill from the stream. Bounded because "best-effort" and
    # "unbounded" together mean a silent grid delays the stream by the ES client's
    # whole retry budget for a name we are willing to do without.
    try:
        async with asyncio.timeout(ctx.settings.webui_grid_timeout_s):
            _, seed_rule_name = await resolve_alert_for_hunt(elastic, ctx.settings, req.alert_id)
    except Exception:
        seed_rule_name = None

    async def stream() -> Any:
        # `investigate` stays a routes-module binding so tests can patch it.
        event_gen = investigate(req.alert_id, ctx=ctx)
        async for name, data in recorded_run(
            request.app.state,
            alert_id=req.alert_id,
            started_by=started_by,
            event_stream=event_gen,
            rule_name=seed_rule_name,
        ):
            yield sse_encode(name, data)

    return EventSourceResponse(stream())


async def _find_alert_search(
    elastic: ElasticClient,
    settings: Settings,
    must: list[dict[str, Any]],
    time_filter: dict[str, Any],
) -> tuple[Any, int]:
    """One bounded, guarded ``must`` + time-window lookup for :func:`find_alert_endpoint`.

    Bounded like the console reads: this endpoint answers an interactive client
    waiting on a row, so it fails fast instead of riding the ES client's full
    retry budget (~90 s at shipped defaults). Grid errors become the house
    503/400 rather than escaping the handler as an unhandled 500 — and, just as
    importantly, rather than being swallowed into the ``no_match`` body, which
    would report an outage as a fact about the caller's telemetry.
    """
    q: dict[str, Any] = {"bool": {"must": must, "filter": [time_filter]}}
    try:
        async with asyncio.timeout(settings.webui_grid_timeout_s):
            result = await elastic.search(
                settings.events_index_pattern,
                q,
                size=1,
                sort=[{"@timestamp": {"order": "desc"}}],
            )
    except (TimeoutError, TransportError) as exc:
        raise HTTPException(status_code=503, detail=_grid_unavailable(exc)) from exc
    except ApiError as exc:
        # An ES ApiError is NOT a TransportError — without this arm an ES 4xx
        # still escapes the tuple above as an unhandled 500.
        raise _es_api_error_http(exc) from exc
    return (result.hits[0] if result.hits else None, result.total)


@router.post(
    "/find-alert",
    response_model=FindAlertResponse,
    dependencies=[Depends(require_api_auth)],
)
async def find_alert_endpoint(
    req: FindAlertRequest,
    settings: Settings = Depends(get_settings_dep),
    elastic: ElasticClient = Depends(get_elastic),
) -> FindAlertResponse:
    """Resolve an alert ES `_id` from row-level context.

    The SO 3.0.0 frontend doesn't embed alert `_id`s in the DOM, only the
    field values shown in each cell (rule.uuid, source.ip, dest.ip,
    timestamp, etc.). A cross-origin API client posts whatever row-level
    context it has here, and we run an ES search to resolve back to a
    concrete alert.

    A grid failure is reported as a grid failure: 503 ``grid_unavailable`` (or
    400 on an ES-rejected query), never the ``found_via="no_match"`` body that
    means "I looked and this row is not in your telemetry".
    """
    must: list[dict[str, Any]] = []
    if req.rule_uuid:
        must.append({"term": {"rule.uuid": req.rule_uuid}})
    if req.source_ip:
        must.append({"term": {"source.ip": req.source_ip}})
    if req.destination_ip:
        must.append({"term": {"destination.ip": req.destination_ip}})
    if req.source_port:
        must.append({"term": {"source.port": req.source_port}})
    if req.destination_port:
        must.append({"term": {"destination.port": req.destination_port}})
    if req.event_module:
        must.append({"term": {"event.module": req.event_module}})
    if req.event_dataset:
        must.append({"term": {"event.dataset": req.event_dataset}})
    if req.rule_name:
        must.append({"match_phrase": {"rule.name": req.rule_name}})

    if not must:
        raise HTTPException(
            status_code=400,
            detail="must provide at least one of: rule_uuid, source_ip, destination_ip, rule_name",
        )

    # Two-stage matching: try a tight ~2s window around the row's timestamp
    # first; if that misses (timestamp couldn't be parsed, clock skew, or
    # the row is older than the default lookback), widen to max_age_minutes.
    parsed_ts: datetime | None = None
    if req.timestamp:
        try:
            parsed_ts = _parse_so_timestamp(req.timestamp)
        except ValueError as e:
            _LOGGER.info("find_alert: could not parse timestamp %r: %s", req.timestamp, e)

    async def _search_with_filter(time_filter: dict[str, Any]) -> tuple[Any, int]:
        return await _find_alert_search(elastic, settings, must, time_filter)

    hit = None
    total = 0
    found_via_stage = "no_match"

    if parsed_ts is not None:
        window = timedelta(seconds=2)
        tight_filter = {
            "range": {
                "@timestamp": {
                    "gte": (parsed_ts - window).isoformat(),
                    "lte": (parsed_ts + window).isoformat(),
                }
            }
        }
        hit, total = await _search_with_filter(tight_filter)
        if hit is not None:
            found_via_stage = "timestamp"

    if hit is None:
        # Fall back to max_age_minutes window. SO analyst views often span
        # 10-24h; the default for this endpoint is set wide enough to cover
        # those without requiring the caller to override.
        wide_filter = {"range": {"@timestamp": {"gte": f"now-{req.max_age_minutes}m"}}}
        hit, total = await _search_with_filter(wide_filter)
        if hit is not None:
            found_via_stage = "lookback"

    if hit is None:
        return FindAlertResponse(
            alert_id=None,
            alert_index=None,
            found_via="no_match",
            candidates_seen=total,
        )

    found_via = ("rule_uuid" if req.rule_uuid else "context") + "+" + found_via_stage
    return FindAlertResponse(
        alert_id=hit["_id"],
        alert_index=hit["_index"],
        found_via=found_via,
        candidates_seen=total,
    )
