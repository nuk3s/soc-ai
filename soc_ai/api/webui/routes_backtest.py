"""Backtest start/status endpoints."""

from __future__ import annotations

import logging
from typing import Any

from fastapi import Depends, HTTPException, Request
from pydantic import BaseModel, Field

from soc_ai.api.security import identify_caller
from soc_ai.api.webui._shared import (
    require_admin_api,
    router,
)
from soc_ai.store import backtests as bt_svc
from soc_ai.store.models import Backtest
from soc_ai.webui import alerts_query as aq
from soc_ai.webui import backtest as backtest_svc

_LOGGER = logging.getLogger(__name__)

# ── Backtest ("prove it on my last N days") ────────────────────────────────────
#
# Replays the agent over a diverse sample of ALREADY-DISPOSITIONED alerts and
# reports how soc-ai's verdicts compare to the analyst's real Security Onion
# disposition. Single-flight background job (BacktestStatus on app.state), the
# same shape as auto-triage. Each sample is a FULL LLM investigation — expensive
# — so the endpoint clamps sample_size to ``settings.backtest_max_sample``.


class BacktestStatusOut(BaseModel):
    active: bool
    backtest_id: str | None = None
    total: int
    replayed: int
    failed: int
    finished_at: str | None = None
    current: str | None = None
    note: str | None = None
    # The finished run's params + scored results (present once complete).
    params: dict[str, Any] | None = None
    results: dict[str, Any] | None = None
    status: str | None = None
    sampled: int | None = None


class BacktestIn(BaseModel):
    window_days: int = Field(default=30, ge=1, le=365)
    sample_size: int = Field(default=backtest_svc.DEFAULT_SAMPLE_SIZE, ge=1)
    min_severity: str | None = None


def _bt_status_out(status: Any) -> BacktestStatusOut:
    """Serialize the in-memory BacktestStatus (live progress, no stored results)."""
    return BacktestStatusOut(
        active=status.active,
        backtest_id=status.backtest_id,
        total=status.total,
        replayed=status.replayed,
        failed=status.failed,
        finished_at=status.finished_at,
        current=status.current,
        note=status.note,
    )


def _bt_row_out(bt: Backtest, *, live: Any = None) -> BacktestStatusOut:
    """Serialize a persisted Backtest row, overlaying live progress when it's the
    active run (so a poll of GET /backtest shows both stored results AND the
    in-flight replayed/failed counters)."""
    active = bool(live and live.active and live.backtest_id == bt.id)
    return BacktestStatusOut(
        active=active,
        backtest_id=bt.id,
        total=(live.total if active else bt.sampled),
        replayed=(live.replayed if active else bt.sampled),
        failed=(live.failed if active else 0),
        finished_at=(bt.finished_at.isoformat() if bt.finished_at else None),
        current=(live.current if active else None),
        note=(live.note if active else None),
        params=bt.params,
        results=bt.results,
        status=bt.status,
        sampled=bt.sampled,
    )


@router.post(
    "/backtest",
    response_model=BacktestStatusOut,
    dependencies=[Depends(require_admin_api)],
)
async def start_backtest(request: Request, body: BacktestIn) -> BacktestStatusOut:
    """Plan + launch a background backtest (single-flight). Poll GET /backtest.

    Samples already-dispositioned alerts from the last ``window_days`` (analyst
    escalated ⇒ expected true-positive; acknowledged-not-escalated ⇒ expected
    false-positive), replays each through the agent, and scores soc-ai's verdicts
    against the human disposition. ``sample_size`` is clamped to
    ``settings.backtest_max_sample`` — each sample is a full LLM investigation.
    Admin-gated (expensive + operator-facing).
    """
    state = request.app.state
    started_by = f"backtest:{await identify_caller(request)}"
    min_sev = (body.min_severity or "").strip().lower() or None
    if min_sev is not None and min_sev not in aq.SEVERITIES:
        min_sev = None
    status = await backtest_svc.start_backtest(
        state,
        window_days=body.window_days,
        sample_size=body.sample_size,
        min_severity=min_sev,
        started_by=started_by,
    )
    return _bt_status_out(status)


@router.get("/backtest", response_model=BacktestStatusOut)
async def backtest_status(request: Request) -> BacktestStatusOut:
    """The current/last backtest: live progress if running, else the stored results."""
    state = request.app.state
    live = backtest_svc.get_status(state)
    async with state.db_sessionmaker() as db:
        bt = await bt_svc.latest(db)
    if bt is None:
        # Never run — return the idle in-memory status.
        return _bt_status_out(live)
    return _bt_row_out(bt, live=live)


@router.get("/backtest/{backtest_id}", response_model=BacktestStatusOut)
async def backtest_by_id(request: Request, backtest_id: str) -> BacktestStatusOut:
    """A specific backtest run by id."""
    state = request.app.state
    live = backtest_svc.get_status(state)
    async with state.db_sessionmaker() as db:
        bt = await bt_svc.get(db, backtest_id)
    if bt is None:
        raise HTTPException(status_code=404, detail={"reason": "backtest_not_found"})
    return _bt_row_out(bt, live=live)
