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
from datetime import UTC, datetime, timedelta
from typing import Any

from fastapi import Depends, Request
from pydantic import BaseModel

from soc_ai.api.webui._shared import _iso_utc, _iso_z, require_admin_api, router
from soc_ai.eval.nightly import run_eval_nightly
from soc_ai.eval.quality import alarm_codes_from_key
from soc_ai.store import quality as quality_svc
from soc_ai.store.models import QualityEvalAttempt

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
    # The grade counts behind agreement_rate. NULL on rows written before
    # migration 0026 — "we never recorded this" and "nothing agreed" are
    # different facts, and the card must not render the first as the second.
    # ``n_partial`` is the one worth showing: a partial critique ("right
    # verdict, thin reasoning") lands in the rate's denominator but not its
    # numerator, so 3 yes + 2 partial reads as the same 0.60 as 3 yes + 2 no.
    n_yes: int | None
    n_partial: int | None
    n_no: int | None
    n_classified: int | None
    fallback_rate: float | None
    error_rate: float
    latency_p50_ms: int | None
    verdict_counts: dict[str, int]
    alarmed: bool
    alarm_reasons: list[str]
    # WHICH condition alarmed, and since when (migration 0027). The reasons
    # above are prose with the run's live numbers baked in, so they can neither
    # be compared across nights nor sorted into headlines: "5 of 5 eval runs
    # errored" is pipeline health, not verdict quality, and the card has to be
    # able to tell them apart. Empty/null on a clean point AND on a pre-0027
    # row, where the condition was never recorded — the card renders the prose
    # in that case rather than inventing a code.
    alarm_codes: list[str]
    alarm_key: str | None
    # When the CURRENT condition started. Older than ``ts`` means the alarm has
    # been ongoing rather than newly raised — the difference between "this keeps
    # firing" and "this is still true".
    alarm_since: str | None
    # Where this run's artifacts (index.jsonl, bundles with the oracle
    # critiques, report.md) were written. The only way to adjudicate an alarm
    # is to read the critiques behind it, so the card links this.
    batch_dir: str | None
    # WHAT WAS RUNNING when the point was measured (migration 0040), so a bend
    # in the trend can be pinned to a change rather than left as weather. All
    # three are null on pre-0040 rows, and ``code_commit`` is also null on any
    # build that was never stamped with one — the honest answer, since the
    # question these fields exist for is precisely where the build changed.
    app_version: str | None
    code_commit: str | None
    analyst_model: str | None


STALE_AFTER = timedelta(hours=48)
"""How old the newest point may be before the trend reads as stale.

The nightly runs once a day, so a point older than two scheduled runs means
at least one run wrote nothing (no eligible alerts, an error) or never
started. One missed night is not called out on purpose: a run that lands late,
or host cron an hour off the in-app schedule, would trip a 24h line most
mornings, and a marker that fires that often is one nobody reads.
"""


class QualityFreshnessOut(BaseModel):
    """When the trend last moved, and what the last attempt did.

    A nightly that finds no eligible alerts writes no row (exit 2), so the
    points alone cannot say whether it ran, and a month-old point looked
    exactly like last night's. No zero row is written for that case: it would
    plot as quality 0, count toward the regression detector's history and
    push a real point out of the 90-row prune. This block carries the fact
    instead.

    Every field here survives a restart. The ``last_attempt_*`` three used to
    read the run-now / scheduler status slot, which lives in process memory:
    null until THIS process had attempted a run, and gone on the next restart.
    Both surfaces that render them test the timestamp for truthiness, so "the
    nightly has never run here" and "it ran last night, exited 2, and I have
    forgotten" resolved to the same silence — beside an empty trend, which is
    an absence being read as an all-clear. They now come from
    ``quality_eval_attempts``, where a null genuinely means no attempt has ever
    been recorded.
    """

    latest_ts: str | None  # the newest row's created_at, ISO-8601 with a Z
    scheduled: bool  # the in-app nightly is enabled
    stale: bool  # scheduled, and the newest row is older than STALE_AFTER
    last_attempt_at: str | None
    last_exit_code: int | None
    last_detail: str | None  # the run's own one-line reason; null on a clean run


class QualityTrendOut(BaseModel):
    points: list[QualityPointOut]  # oldest → newest, ready to plot left-to-right
    freshness: QualityFreshnessOut


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
    Empty list = the nightly has never written a point; the card renders its
    "schedule soc-ai eval-nightly" empty state from that, not from an error.
    ``freshness`` says whether it has TRIED since this process started, and
    how old the newest point is against the schedule.
    """
    state = request.app.state
    async with state.db_sessionmaker() as db:
        rows = await quality_svc.recent_snapshots(db, limit=30)
        # Same session: the two answer one question together — "has it run, and
        # did it produce anything" — and reading them apart could show a point
        # from after the attempt that wrote it.
        attempt = await quality_svc.latest_attempt(db)
    # The store returns newest-first (its natural "recent" order); the chart
    # wants chronological so a plain reversed() keeps both callers simple.
    return QualityTrendOut(
        freshness=_freshness_out(
            newest=rows[0].created_at if rows else None,
            scheduled=bool(state.settings.eval_nightly_enabled),
            attempt=attempt,
            now=datetime.now(UTC),
        ),
        points=[
            QualityPointOut(
                id=r.id,
                ts=_iso_utc(r.created_at),
                mode=r.mode,
                n_ok=r.n_ok,
                n_error=r.n_error,
                agreement_rate=r.agreement_rate,
                n_yes=r.n_yes,
                n_partial=r.n_partial,
                n_no=r.n_no,
                n_classified=r.n_classified,
                fallback_rate=r.fallback_rate,
                error_rate=r.error_rate,
                latency_p50_ms=r.latency_p50_ms,
                verdict_counts={str(k): int(v) for k, v in (r.verdict_counts or {}).items()},
                alarmed=r.alarmed,
                alarm_reasons=list(r.alarm_reasons or []),
                alarm_codes=alarm_codes_from_key(r.alarm_key),
                alarm_key=r.alarm_key,
                # _iso_utc renders None as "", which a "since when" field must
                # not become — an empty string is a value the card would try to
                # parse. Null is the honest answer for a point with no alarm.
                alarm_since=_iso_utc(r.alarm_since) if r.alarm_since else None,
                batch_dir=r.batch_dir,
                app_version=r.app_version,
                code_commit=r.code_commit,
                analyst_model=r.analyst_model,
            )
            for r in reversed(rows)
        ],
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


def _freshness_out(
    *,
    newest: datetime | None,
    scheduled: bool,
    attempt: QualityEvalAttempt | None,
    now: datetime,
) -> QualityFreshnessOut:
    """Reduce the newest point, the schedule flag and the newest attempt to the block.

    ``stale`` needs both a schedule and a row: with the nightly off there is no
    run to have missed, and with no row there is no point to be old (the card's
    empty state covers that, and the attempt fields say why it is empty).

    ``attempt`` is the durable row, not the process's status slot. The slot
    still exists — it is what makes run-now single-flight — but it is no longer
    the source of anything an operator reads, because it forgets on restart and
    the reader cannot tell that apart from never having run.
    """
    stale = False
    if scheduled and newest is not None:
        # Store timestamps are naive UTC; the clock passed in is aware.
        newest_aware = newest if newest.tzinfo else newest.replace(tzinfo=UTC)
        stale = now - newest_aware > STALE_AFTER
    return QualityFreshnessOut(
        latest_ts=_iso_z(newest),
        scheduled=scheduled,
        stale=stale,
        # The store keeps naive UTC, like every other timestamp here; the block
        # keeps one convention, so it is re-rendered with a Z.
        last_attempt_at=_iso_z(attempt.attempted_at) if attempt else None,
        last_exit_code=attempt.exit_code if attempt else None,
        # Empty means a clean run had nothing to add, which is not the same as
        # a run that said nothing — null is what the card tests.
        last_detail=(attempt.detail or None) if attempt else None,
    )


async def _quality_eval_worker(state: Any, *, trigger: str = "manual") -> None:
    """Background worker for run-now and the scheduler. Never raises; always
    releases the single-flight slot and records the outcome.

    ``trigger`` separates the two callers on the durable row, because they
    answer different questions: an operator asking "did last night's nightly
    run" must not be reassured by their own click on the run-now button.
    """
    status = _get_quality_eval_status(state)
    try:
        # Bind the server's own audit logger into the alarm: a second logger in
        # this process would be a second chain head competing for the same
        # sequence numbers (soc_ai.audit.logger).
        app_audit = getattr(state, "audit", None)

        async def fire_alarm(settings: Any, **kw: Any) -> None:
            await _fire_alarm_lazily(settings, audit=app_audit, **kw)

        result = await run_eval_nightly(
            state.settings,
            emit=lambda line: _LOGGER.info("quality eval: %s", line),
            fire_alarm=fire_alarm,
        )
        status.last_exit_code = result.exit_code
        status.last_detail = result.detail
        if result.exit_code != 0:
            # A run that wrote nothing (exit 2: no eligible alerts; exit 5:
            # failed) raises nothing, and the status slot above is process
            # memory. This line is the only record of the attempt that
            # survives a restart, once per attempt, with the run's own reason.
            _LOGGER.warning("quality eval: exit %d: %s", result.exit_code, result.detail)
    except Exception as e:  # the eval must never take the app down
        _LOGGER.exception("quality eval run failed")
        status.last_exit_code = 5
        status.last_detail = f"{type(e).__name__}: {e}"
    finally:
        now = datetime.now(tz=UTC)
        status.last_run = now.isoformat()
        # The durable half, and the one every surface reads. Written HERE, in
        # the finally, so an attempt that raised is recorded exactly like one
        # that returned — a failure that leaves no trace is the case this table
        # exists for. Best-effort: the eval must never take the app down, and
        # that has to include its own bookkeeping. The log line below is what
        # is left if even this fails.
        try:
            async with state.db_sessionmaker() as db:
                await quality_svc.record_attempt(
                    db,
                    trigger=trigger,
                    exit_code=status.last_exit_code if status.last_exit_code is not None else 5,
                    detail=status.last_detail,
                    now=now.replace(tzinfo=None),
                )
        except Exception:
            _LOGGER.warning("quality eval: could not record the attempt", exc_info=True)
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
    status._task = asyncio.create_task(_quality_eval_worker(state, trigger="manual"))
    return _status_out(status)


@router.get(
    "/quality/eval/status",
    response_model=QualityEvalStatusOut,
    dependencies=[Depends(require_admin_api)],
    tags=["quality"],
)
async def get_quality_eval_status(request: Request) -> QualityEvalStatusOut:
    return _status_out(_get_quality_eval_status(request.app.state))
