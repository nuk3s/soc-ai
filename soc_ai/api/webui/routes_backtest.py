"""Backtest start/status endpoints."""

from __future__ import annotations

import logging
from typing import Any

from elastic_transport import TransportError
from elasticsearch import ApiError
from fastapi import Depends, HTTPException, Request
from pydantic import BaseModel, Field

from soc_ai.api.security import identify_caller
from soc_ai.api.webui._shared import (
    require_admin_api,
    router,
)
from soc_ai.api.webui.routes_alerts import _GRID_UNAVAILABLE, _es_api_error_http
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


def _bt_latest_out(bt: Backtest, *, live: Any) -> BacktestStatusOut:
    """The last stored run, with the NEWEST attempt's state stated over the top.

    ``GET /backtest`` answers one question — what is this console's backtest
    doing right now — and the answer lives in two places. A run is claimed and
    active from the moment the sampling search goes out, and its row is created
    only when that search RETURNS: so a run still sampling has no row yet, and a
    run that died in its sampling read never gets one at all. Serving the stored
    row alone answered both of those with the PREVIOUS run's finished results,
    ``active: false``, ``note: null``. On any instance that has completed a
    backtest even once, that hid today's failure behind last week's score — the
    durable failure note and the sampling panel were reachable only on a
    first-ever run, i.e. only on an empty database.

    The stored row is merged, not replaced. A score that was really measured is
    not deleted by today's outage: it stays, dated ("Ran …") on the screen, with
    the newest attempt's state over it.
    """
    out = _bt_row_out(bt, live=live)
    if out.active or live is None or live.backtest_id is not None:
        # Either the live run IS this row, or there is nothing newer than it: a
        # run that got as far as a row left its id here, and that row is this one
        # (``bt`` is the latest).
        return out
    if live.active:
        # The sampling search is still out. Nothing has been sampled yet, so the
        # live counters are the honest ones — and ``active`` with no
        # ``backtest_id`` is the shape that says "reading, not replaying", so it
        # has to survive the merge or the phase cannot be named.
        return out.model_copy(
            update={
                "active": True,
                "backtest_id": None,
                "total": live.total,
                "replayed": live.replayed,
                "failed": live.failed,
                "current": live.current,
                "note": live.note,
            }
        )
    if live.note:
        # An attempt that never reached a row, and necessarily newer than the
        # stored one. This note is all the analyst has once the inline error is
        # gone; dropping it is how a failed run came to leave no trace at all.
        return out.model_copy(update={"note": live.note})
    return out


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

    The grid budget for this call lives one level down, wrapped around the
    sampling search in :func:`soc_ai.webui.backtest.start_backtest`, and NOT
    around this handler: the replay it launches is N full investigations over a
    window up to a year wide, so a console budget meant for one read has no
    business anywhere near it. Bound the read, not the work. An expiry arrives
    here as the ``TimeoutError`` the 503 arm below already answers.
    """
    state = request.app.state
    started_by = f"backtest:{await identify_caller(request)}"
    min_sev = (body.min_severity or "").strip().lower() or None
    if min_sev is not None and min_sev not in aq.SEVERITIES:
        min_sev = None
    try:
        status = await backtest_svc.start_backtest(
            state,
            window_days=body.window_days,
            sample_size=body.sample_size,
            min_severity=min_sev,
            started_by=started_by,
        )
    except (TimeoutError, TransportError) as exc:
        # The sampling query could not read the grid. Answering 200 with "no
        # dispositioned alerts in the window to replay" told the admin, as a fact
        # about their own triage history, that they had never dispositioned
        # anything — during an outage, on the screen built to earn their trust.
        raise HTTPException(status_code=503, detail=_GRID_UNAVAILABLE) from exc
    except ApiError as exc:
        raise _es_api_error_http(exc) from exc
    return _bt_status_out(status)


@router.get("/backtest", response_model=BacktestStatusOut)
async def backtest_status(request: Request) -> BacktestStatusOut:
    """The current/last backtest: the newest attempt's state over the stored results.

    See :func:`_bt_latest_out` for why the two are merged rather than one
    winning — an attempt that has not produced a row yet (still sampling) or
    never will (its sampling read failed) is invisible in the stored row, and
    that is the state this screen most needs to report.
    """
    state = request.app.state
    live = backtest_svc.get_status(state)
    async with state.db_sessionmaker() as db:
        bt = await bt_svc.latest(db)
    if bt is None:
        # Never run — return the idle in-memory status.
        return _bt_status_out(live)
    return _bt_latest_out(bt, live=live)


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
