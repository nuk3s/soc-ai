"""Quality-trend read-model (I4): the nightly micro-eval history for the dashboard.

One admin-gated GET over the ``quality_snapshots`` table — the same pure
read-model idiom as ``/config/egress-policy``: no writes, no derived state the
CLI didn't already persist. In particular the ALARM is served exactly as the
nightly recorded it (``alarmed``/``alarm_reasons`` were computed at write time
against history that may since have been pruned), so the card can never
re-litigate an alarm into a different answer than the one that paged on-call.
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from fastapi import Depends, Request
from pydantic import BaseModel

from soc_ai.api.webui._shared import _iso_utc, require_admin_api, router
from soc_ai.eval.nightly import run_eval_nightly
from soc_ai.store import quality as quality_svc

_LOGGER = logging.getLogger(__name__)


class QualityPointOut(BaseModel):
    """One nightly snapshot, in the light shape the sparkline plots.

    ``mode`` labels how the point was measured (``graded`` = oracle critique,
    ``local`` = zero-egress proxies) — the card badges it because the two are
    different instruments: a graded 0.8 agreement and a local null are not
    comparable, and pretending otherwise on one line would be dishonest.
    """

    id: int
    ts: str  # ISO-8601, timezone-aware (store timestamps are naive UTC)
    mode: str  # "local" | "graded"
    n_ok: int
    n_error: int
    agreement_rate: float | None
    fallback_rate: float | None
    error_rate: float
    latency_p50_ms: int | None
    verdict_counts: dict[str, int]
    alarmed: bool
    alarm_reasons: list[str]


class QualityTrendOut(BaseModel):
    points: list[QualityPointOut]  # oldest → newest, ready to plot left-to-right


@router.get(
    "/quality/trend",
    response_model=QualityTrendOut,
    dependencies=[Depends(require_admin_api)],
    tags=["quality"],
)
async def get_quality_trend(request: Request) -> QualityTrendOut:
    """The last 30 nightly quality snapshots, oldest first.

    Feeds the dashboard's Quality card. Admin-gated like the other posture
    read-models (config, egress policy): the trend names the batch artifact
    paths and exposes operational health an analyst role doesn't need.
    Empty list = the nightly has never run — the card renders its
    "schedule soc-ai eval-nightly" empty state from that, not from an error.
    """
    async with request.app.state.db_sessionmaker() as db:
        rows = await quality_svc.recent_snapshots(db, limit=30)
    # The store returns newest-first (its natural "recent" order); the chart
    # wants chronological so a plain reversed() keeps both callers simple.
    return QualityTrendOut(
        points=[
            QualityPointOut(
                id=r.id,
                ts=_iso_utc(r.created_at),
                mode=r.mode,
                n_ok=r.n_ok,
                n_error=r.n_error,
                agreement_rate=r.agreement_rate,
                fallback_rate=r.fallback_rate,
                error_rate=r.error_rate,
                latency_p50_ms=r.latency_p50_ms,
                verdict_counts={str(k): int(v) for k, v in (r.verdict_counts or {}).items()},
                alarmed=r.alarmed,
                alarm_reasons=list(r.alarm_reasons or []),
            )
            for r in reversed(rows)
        ]
    )


# ── Run-now + in-app schedule (schedulable from the UI, 2026-07-16) ─────────
# Mirrors the discovery scan-now shape: one single-flight status slot on
# app.state, shared by the POST below AND main._eval_nightly_loop so a manual
# run and a scheduled run can never overlap.


@dataclass
class _QualityEvalStatus:
    running: bool = False
    last_run: str | None = None  # tz-aware ISO of the last COMPLETED attempt
    last_exit_code: int | None = None
    last_detail: str = ""
    # UTC date ("YYYY-MM-DD") of the last SCHEDULED attempt — the loop's
    # once-per-day guard, covering failed runs that write no snapshot.
    last_scheduled_date: str | None = None
    _task: asyncio.Task[None] | None = field(default=None, repr=False)


def _get_quality_eval_status(state: Any) -> _QualityEvalStatus:
    if not hasattr(state, "_quality_eval_status"):
        state._quality_eval_status = _QualityEvalStatus()
    return state._quality_eval_status  # type: ignore[no-any-return]


async def _quality_eval_worker(state: Any) -> None:
    """Background worker for run-now and the scheduler. Never raises; always
    releases the single-flight slot and records the outcome for the status GET."""
    status = _get_quality_eval_status(state)
    try:
        result = await run_eval_nightly(
            state.settings,
            emit=lambda line: _LOGGER.info("quality eval: %s", line),
            fire_alarm=_fire_alarm_lazily,
        )
        status.last_exit_code = result.exit_code
        status.last_detail = result.detail
    except Exception as e:  # the eval must never take the app down
        _LOGGER.exception("quality eval run failed")
        status.last_exit_code = 5
        status.last_detail = f"{type(e).__name__}: {e}"
    finally:
        status.last_run = datetime.now(tz=UTC).isoformat()
        status.running = False


async def _fire_alarm_lazily(settings: Any, **kw: Any) -> None:
    """Regression alarm side effects — the CLI's implementation, lazily bound
    so importing this routes module never drags the CLI in at startup."""
    from soc_ai.cli import _fire_quality_alarm  # noqa: PLC0415 - lazy

    await _fire_quality_alarm(settings, **kw)


class QualityEvalStatusOut(BaseModel):
    running: bool
    last_run: str | None = None
    last_exit_code: int | None = None
    last_detail: str = ""
    note: str | None = None


def _status_out(status: _QualityEvalStatus, note: str | None = None) -> QualityEvalStatusOut:
    return QualityEvalStatusOut(
        running=status.running,
        last_run=status.last_run,
        last_exit_code=status.last_exit_code,
        last_detail=status.last_detail,
        note=note,
    )


@router.post(
    "/quality/eval/run",
    response_model=QualityEvalStatusOut,
    dependencies=[Depends(require_admin_api)],
    tags=["quality"],
)
async def start_quality_eval_run(request: Request) -> QualityEvalStatusOut:
    """Run the quality micro-eval NOW, in the background (single-flight).

    The same core the CLI and the in-app scheduler use — n real
    investigations at concurrency 1, one trend point. A second POST while a
    run is in flight simply reports it (never a double batch).
    """
    state = request.app.state
    status = _get_quality_eval_status(state)
    if status.running:
        return _status_out(status, note="already running")
    status.running = True  # claim the single-flight slot before scheduling
    status._task = asyncio.create_task(_quality_eval_worker(state))
    return _status_out(status)


@router.get(
    "/quality/eval/status",
    response_model=QualityEvalStatusOut,
    dependencies=[Depends(require_admin_api)],
    tags=["quality"],
)
async def get_quality_eval_status(request: Request) -> QualityEvalStatusOut:
    return _status_out(_get_quality_eval_status(request.app.state))
