"""Backtest start, status and cancel endpoints."""

from __future__ import annotations

import dataclasses
import logging
from typing import Annotated, Any

from elastic_transport import TransportError
from elasticsearch import ApiError
from fastapi import Depends, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field, StringConstraints

from soc_ai.api.security import identify_caller
from soc_ai.api.webui._errors import api_error
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

# The audit session of a backtest cancel.
_AUDIT_SESSION = "backtest"

# ── Backtest ("prove it on my last N days") ────────────────────────────────────
#
# Replays the agent over a diverse sample of ALREADY-DISPOSITIONED alerts and
# reports how soc-ai's verdicts compare to the analyst's real Security Onion
# disposition. Single-flight background job (BacktestStatus on app.state), the
# same shape as auto-triage. Each sample is a FULL LLM investigation — expensive
# — so the endpoint clamps sample_size to ``settings.backtest_max_sample``.


class BacktestEstimateOut(BaseModel):
    """The median wall time of one replay, and what it was read from."""

    seconds_per_alert: float
    # How many completed runs the median covers.
    runs: int
    # "backtest": the recent backtest replays. "investigations": the store
    # holds no replay, so the median reads the recent completed investigations.
    basis: str


class BacktestRunSummaryOut(BaseModel):
    """One stored run in the list of past runs. A run that did not complete
    carries no rates."""

    backtest_id: str
    status: str
    started_at: str | None = None
    finished_at: str | None = None
    sampled: int | None = None
    requested: int | None = None
    window_days: int | None = None
    min_severity: str | None = None
    # True for a run over an explicit list of alerts: no window applies.
    listed: bool = False
    agreement_rate: float | None = None
    fp_agreement_rate: float | None = None
    missed_tp: int | None = None
    human_tp: int | None = None
    human_fp: int | None = None


class BacktestRunsOut(BaseModel):
    runs: list[BacktestRunSummaryOut]


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
    # The newest attempt when it started no run: {"reason", "hint"}. It sits
    # beside the stored run and never changes it. A note merged onto the stored
    # run read as that run's own note (fleet 2026-10-01, RO11).
    refused: dict[str, str] | None = None
    # How many alerts the operator asked for, and why fewer were replayed.
    # "requested 20, replayed 14" had no explanation on the screen (RO20).
    requested: int | None = None
    skipped_reason: str | None = None
    # The alert ids the run replays, in replay order. Send the list as
    # ``alert_ids`` to replay the same alerts again.
    alert_ids: list[str] | None = None
    # The cost of the next run, for the console to state before it starts
    # (dogfood 2026-10-19, R5-I9). ``max_sample`` is the server cap on a
    # sample. ``estimate`` is the median time of one replay, or null when the
    # store holds no completed run. GET /backtest serves both while no run is
    # active; every other answer leaves them null.
    max_sample: int | None = None
    estimate: BacktestEstimateOut | None = None
    # An operator asked the live run to stop after the alert in flight
    # (R5-I9). True only while that run is active. A stored run that stopped
    # on a cancel has status "cancelled" and a ``cancel`` block in results.
    cancel_requested: bool = False


# One alert id of an explicit list: an ES ``_id``.
AlertId = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=256)]


class BacktestIn(BaseModel):
    # An unknown key is refused. {"sample": -5} used to start a full default
    # run of 14 replays, because the misspelt key was ignored (RA20).
    model_config = ConfigDict(extra="forbid")

    window_days: int = Field(default=30, ge=1, le=365)
    sample_size: int = Field(default=backtest_svc.DEFAULT_SAMPLE_SIZE, ge=1)
    min_severity: str | None = None
    # An explicit sample: replay exactly these alerts, in this order, and skip
    # the sampling. Each arm of an experiment replays the same alerts.
    # ``window_days``, ``sample_size`` and ``min_severity`` do not apply to it.
    alert_ids: list[AlertId] | None = Field(
        default=None, min_length=1, max_length=backtest_svc.MAX_LISTED_ALERTS
    )


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
        refused=status.refused,
        alert_ids=status.alert_ids,
        cancel_requested=bool(status.active and status.cancel_requested),
    )


def _bt_row_out(
    bt: Backtest, *, live: Any = None, results: dict[str, Any] | None = None
) -> BacktestStatusOut:
    """Serialize a persisted Backtest row, overlaying live progress when it's the
    active run (so a poll of GET /backtest shows both stored results AND the
    in-flight replayed/failed counters).

    ``results`` is the served form of ``bt.results`` (:func:`_served_results`).
    Left out, the stored results are served with the current caveat."""
    active = bool(live and live.active and live.backtest_id == bt.id)
    if results is None:
        results = backtest_svc.served_results(bt.results)
    return BacktestStatusOut(
        active=active,
        backtest_id=bt.id,
        total=(live.total if active else bt.sampled),
        replayed=(live.replayed if active else bt.sampled),
        failed=(live.failed if active else 0),
        finished_at=backtest_svc.iso_utc(bt.finished_at),
        current=(live.current if active else None),
        note=(live.note if active else None),
        params=bt.params,
        results=results,
        status=bt.status,
        sampled=bt.sampled,
        requested=_requested(bt.params),
        skipped_reason=(
            None
            if active
            else backtest_svc.skipped_reason(
                bt.params, bt.sampled, cancel=(bt.results or {}).get("cancel")
            )
        ),
        alert_ids=_replayed_ids(bt),
        cancel_requested=bool(active and live.cancel_requested),
    )


async def _served_results(db: Any, bt: Backtest) -> dict[str, Any] | None:
    """The run's results as the API serves them: the current caveat, the new
    metric names, and the replay id on each row. A row stored before the id
    was recorded gets it from the replays that ran inside the run."""
    return await backtest_svc.results_with_replay_ids(
        db,
        results=backtest_svc.served_results(bt.results),
        started=bt.created_at,
        finished=bt.finished_at,
    )


def _replayed_ids(bt: Backtest) -> list[str] | None:
    """The ids the run replayed, else the ids it planned to replay."""
    for record in (bt.results, bt.params):
        ids = (record or {}).get("alert_ids")
        if isinstance(ids, list):
            return [str(alert_id) for alert_id in ids]
    return None


def _requested(params: dict[str, Any] | None) -> int | None:
    if not params:
        return None
    value = params.get("requested_sample_size") or params.get("sample_size")
    return int(value) if value else None


def _bt_latest_out(
    bt: Backtest, *, live: Any, results: dict[str, Any] | None = None
) -> BacktestStatusOut:
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
    out = _bt_row_out(bt, live=live, results=results)
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
    if live.refused:
        # An attempt that never reached a row, and necessarily newer than the
        # stored one. This refusal is all the analyst has once the inline error
        # is gone; dropping it is how a failed run came to leave no trace at
        # all. It rides beside the stored run, which stays as it was.
        return out.model_copy(update={"refused": live.refused})
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
    ``settings.backtest_max_sample``. Each sampled alert is one investigation by
    the model.
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
        raise api_error(
            422,
            "bad_request",
            f"min_severity accepts one of these values: {', '.join(aq.SEVERITIES)}. "
            "Leave it out for every severity.",
        )
    try:
        status = await backtest_svc.start_backtest(
            state,
            window_days=body.window_days,
            sample_size=body.sample_size,
            min_severity=min_sev,
            started_by=started_by,
            alert_ids=body.alert_ids,
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
    # A snapshot of the live status, taken BEFORE the store read. The run writes
    # its final row and only then clears ``active``. Read in this order, an idle
    # snapshot means the row below is final. The route read the live object
    # after the store read, so a run that ended in between answered "running"
    # with active false. That failed the v1.6.0 release run on a loaded runner.
    live = dataclasses.replace(backtest_svc.get_status(state))
    estimate: dict[str, Any] | None = None
    results: dict[str, Any] | None = None
    async with state.db_sessionmaker() as db:
        bt = await bt_svc.latest(db)
        if bt is not None:
            results = await _served_results(db, bt)
        if not live.active:
            # The cost of the NEXT run. A poll during a run does not need it.
            estimate = await backtest_svc.replay_estimate(db)
    cost = {
        "max_sample": (None if live.active else int(state.settings.backtest_max_sample)),
        "estimate": (BacktestEstimateOut(**estimate) if estimate else None),
    }
    if bt is None:
        # Never run — return the idle in-memory status.
        return _bt_status_out(live).model_copy(update=cost)
    return _bt_latest_out(bt, live=live, results=results).model_copy(update=cost)


@router.post(
    "/backtest/{backtest_id}/cancel",
    response_model=BacktestStatusOut,
    dependencies=[Depends(require_admin_api)],
)
async def cancel_backtest(request: Request, backtest_id: str) -> BacktestStatusOut:
    """Stop a running backtest after the alert in flight (R5-I9).

    The stop is cooperative. The replay in flight finishes, no new alert
    starts, and the run ends ``cancelled`` with the results of the alerts it
    finished. The request is held on the server, so ``GET /backtest`` serves
    ``cancel_requested`` until the run ends.

    404 when no run has the id. 409 ``not_running`` when the run is not the
    live one, and 409 ``cancel_requested`` when a cancel of it is pending.
    Admin-gated like the start. A taken cancel writes a
    ``backtest_cancelled`` audit record.
    """
    state = request.app.state
    async with state.db_sessionmaker() as db:
        bt = await bt_svc.get(db, backtest_id)
    if bt is None:
        raise api_error(
            404,
            "backtest_not_found",
            "soc-ai has no backtest run with this id. Open the Backtest page for the last run.",
        )
    caller = await identify_caller(request)
    refusal = backtest_svc.request_cancel(state, backtest_id, by=caller)
    if refusal == backtest_svc.CANCEL_REQUESTED:
        raise api_error(
            409,
            "cancel_requested",
            "A cancel of this backtest is already pending. "
            "The backtest stops after the current alert.",
        )
    if refusal is not None:
        raise api_error(
            409,
            "not_running",
            f"This backtest is not running. Its status is {bt.status}. There is nothing to cancel.",
        )
    live = backtest_svc.get_status(state)
    await _audit_cancel(
        request,
        {
            "backtest_id": backtest_id,
            "finished": live.replayed + live.failed,
            "total": live.total,
        },
        user=caller,
    )
    return _bt_row_out(bt, live=live, results=backtest_svc.served_results(bt.results))


async def _audit_cancel(request: Request, payload: dict[str, Any], *, user: str) -> None:
    """One audit record for a taken cancel. Best-effort: the cancel already stands."""
    try:
        audit = getattr(request.app.state, "audit", None)
        if audit is not None:
            await audit.log_kind(_AUDIT_SESSION, "backtest_cancelled", payload, user=user)
    except Exception:
        _LOGGER.warning("backtest cancel audit write failed (continuing)", exc_info=True)


@router.get("/backtests", response_model=BacktestRunsOut)
async def backtest_runs(request: Request, limit: int = 20) -> BacktestRunsOut:
    """The stored runs, newest first, as a summary for each (R5-I10).

    ``GET /backtest/{id}`` serves the full report of one run. ``limit`` is
    from 1 to 100.
    """
    if not 1 <= limit <= 100:
        raise api_error(422, "bad_request", "limit must be from 1 to 100.")
    async with request.app.state.db_sessionmaker() as db:
        rows = await bt_svc.list_recent(db, limit=limit)
    return BacktestRunsOut(
        runs=[BacktestRunSummaryOut(**backtest_svc.run_summary(bt)) for bt in rows]
    )


@router.get("/backtest/{backtest_id}", response_model=BacktestStatusOut)
async def backtest_by_id(request: Request, backtest_id: str) -> BacktestStatusOut:
    """A specific backtest run by id."""
    state = request.app.state
    live = backtest_svc.get_status(state)
    async with state.db_sessionmaker() as db:
        bt = await bt_svc.get(db, backtest_id)
        results = await _served_results(db, bt) if bt is not None else None
    if bt is None:
        raise api_error(
            404,
            "backtest_not_found",
            "soc-ai has no backtest run with this id. Open the Backtest page for the last run.",
        )
    return _bt_row_out(bt, live=live, results=results)
