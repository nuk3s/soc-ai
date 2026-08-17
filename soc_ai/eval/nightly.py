"""Shared nightly quality-eval runner.

One implementation behind three triggers: the ``soc-ai eval-nightly`` CLI
(host cron), the Config-console "Run now" endpoint, and the in-app schedule
loop (``eval_nightly_enabled``). Extracted from the CLI's inlined ``_go()``
closure so the app can run the eval in-process — the nightly used to be
schedulable only from host cron (user requirement 2026-07-16: schedulable
from the UI).

The micro-eval itself is unchanged: investigate ``quality_nightly_n`` real
alerts at concurrency 1 through the existing batch machinery, aggregate,
land ONE row in ``quality_snapshots`` (pruned to the newest 90), and alarm
(audit event + opt-in webhook) when the point regresses against its own
trailing same-mode history.

Every alarmed point is RECORDED, but only a change of condition is REPORTED —
see :func:`_record_trend_point` for why those are different questions.
"""

from __future__ import annotations

import contextlib
import os
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

# Exit codes shared with the CLI (documented in `soc-ai eval-nightly --help`):
# 0 ok · 2 no eligible alerts (no snapshot) · 4 aborted-but-written · 5 error.
EXIT_OK = 0
EXIT_NO_ALERTS = 2
EXIT_ABORTED = 4
EXIT_ERROR = 5

# Bundle directory for callers that don't name one (the in-app scheduler and
# the Config-console "Run now" — i.e. every unattended container run).
#
# It is a SIBLING OF THE DATA DIR rather than a relative path, because the
# relative default resolved against the container's WORKDIR (/opt/soc-ai),
# which is not a volume: every `docker compose up -d` recreate deleted every
# bundle, and with them the oracle critiques that are the only evidence behind
# an alarm on the quality trend. On 2026-08-07 a recreate destroyed the
# artifacts for both of that day's alarms while they were being diagnosed.
# In the packaged layout every persisted directory lives under one root
# (/var/lib/soc-ai/{data,blocklists,maxmind,...}), so deriving from
# ``soc_ai_data_dir`` puts bundles on the volume docker-compose.yml mounts
# without inventing a second source of truth for the install's data root.
_BUNDLE_DIR_NAME = "evals"

# What a host/dev install gets: a relative data dir means there is no packaged
# root to sit inside, so keep the historical ./evals.
_RELATIVE_BUNDLE_DIR = Path(_BUNDLE_DIR_NAME)


def resolve_out_dir(settings: Any, out_dir: str | Path | None) -> tuple[Path, str | None]:
    """Pick the batch-artifact directory. Returns ``(dir, warning)``.

    An explicit *out_dir* (the CLI's ``--out-dir``) always wins. Otherwise the
    bundles land beside the persisted data dir — see :data:`_BUNDLE_DIR_NAME`
    for why that matters more than it looks.

    The warning exists for one failure mode: a named volume mounted at a path
    the image never created is owned by root, so the container user cannot
    write it. Falling back keeps the unattended nightly producing trend points
    instead of failing every night, but silently writing to a directory the
    next recreate will delete is exactly the bug this function fixes — so the
    caller surfaces the reason.
    """
    if out_dir is not None:
        return Path(out_dir), None

    data_dir = Path(getattr(settings, "soc_ai_data_dir", _BUNDLE_DIR_NAME))
    if not data_dir.is_absolute():
        return _RELATIVE_BUNDLE_DIR, None

    target = data_dir.parent / _BUNDLE_DIR_NAME
    try:
        target.mkdir(parents=True, exist_ok=True)
        writable = os.access(target, os.W_OK)
    except OSError as e:
        return _RELATIVE_BUNDLE_DIR, f"cannot use {target} for eval bundles ({e}); using ./evals"
    if not writable:
        return (
            _RELATIVE_BUNDLE_DIR,
            f"cannot use {target} for eval bundles (not writable by this user); "
            "using ./evals — these artifacts will NOT survive a container recreate",
        )
    return target, None


@dataclass
class NightlyRunResult:
    exit_code: int
    mode: str
    # Set on any run that wrote a snapshot (exit 0 / 4); None on 2 / 5.
    metrics: Any | None = None
    batch_dir: str | None = None
    alarm_reasons: list[str] | None = None
    # The condition this point recorded (sorted rule codes) and whether it is a
    # CHANGE from the previous same-mode point. Only a change fires side
    # effects; ``alarm_reasons`` stays populated for every alarmed run, so a
    # caller printing the run's outcome still reports a persisting condition.
    alarm_key: str | None = None
    alarm_is_new: bool = False
    # One analyst-facing line for status surfaces / error detail on 2 / 5.
    detail: str = ""


def resolve_mode(settings: Any, *, graded: bool = False, local: bool = False) -> str:
    """Explicit flag wins; otherwise follow the install's oracle posture —
    ``oracle_enabled`` is the operator's standing declaration that cloud-oracle
    egress is acceptable, so it gates the nightly grader too."""
    if graded:
        return "graded"
    if local:
        return "local"
    return "graded" if settings.oracle_enabled else "local"


@dataclass(frozen=True)
class AlarmOutcome:
    """What one recorded point means: what it SAYS, and whether it is NEWS.

    Two separate questions that the pre-0027 code conflated into one bare
    ``if reasons``. ``reasons`` is what the row stores — a measurement, repeated
    honestly for as long as the condition holds. ``is_transition`` is the only
    thing that may fire a side effect.
    """

    reasons: list[str]
    alarm_key: str | None
    alarm_since: datetime | None
    is_transition: bool


async def _record_trend_point(
    db: Any,
    *,
    metrics: Any,
    mode: str,
    alarm_drop: float,
    batch_dir: str,
) -> AlarmOutcome:
    """Read same-mode history, run the detector, insert + prune — one txn.

    Split out of the run function so the read → decide → write sequence stays
    one readable unit: the decision MUST be made against history that excludes
    the row being written, and the write must carry the counts the next night's
    decision will pool.

    **The transition rule lives here, not in the detector.** The detector has no
    memory by design, so a condition that persists is re-reported every run that
    re-observes it — prod rows 9/10/11 are one "agreement 0.80 against a median
    of 1.00" condition that paged three times in 27 hours, and the reason
    strings could not be compared to notice, because each embeds that run's live
    numbers. So the row always records what was measured (``alarmed`` and
    ``alarm_reasons`` exactly as decided — a suppressed alarm must never read as
    a clean night on the trend), and only a change of ``alarm_key`` against the
    previous SAME-MODE row is reported as new.

    A previous row with a NULL key is treated as UNKNOWN, not as "same": it is
    either a clean night or a pre-0027 row, and firing one extra time after an
    upgrade is recoverable where a swallowed first page is not.
    """
    from soc_ai.eval.quality import (  # noqa: PLC0415 - lazy: keep module import light
        BASELINE_WINDOW,
        TrendPoint,
        alarm_key_for,
        detect_regression,
    )
    from soc_ai.store import quality as quality_store  # noqa: PLC0415 - lazy
    from soc_ai.store.auth import utcnow  # noqa: PLC0415 - lazy

    # BASELINE_WINDOW, not the 7 the median rules use: the agreement test POOLS
    # these counts into one baseline rate, and seven nights of five grades is
    # too few to tell a bad week from a bad model. The detector slices its own
    # median window off the front — the store returns newest-first, which that
    # slice relies on.
    history = await quality_store.recent_snapshots(db, limit=BASELINE_WINDOW, mode=mode)
    reasons = detect_regression(
        metrics,
        [
            TrendPoint(
                agreement_rate=h.agreement_rate,
                fallback_rate=h.fallback_rate,
                n_yes=h.n_yes,
                n_classified=h.n_classified,
            )
            for h in history
        ],
        alarm_drop=alarm_drop,
    )

    # Same-mode, newest-first — so this is the point an operator would compare
    # tonight's card against.
    previous = history[0] if history else None
    alarm_key = alarm_key_for(reasons)
    is_transition = alarm_key is not None and alarm_key != (
        previous.alarm_key if previous is not None else None
    )
    alarm_since = None
    if alarm_key is not None:
        # Carried forward while the condition holds, so the card can say
        # "ongoing since <date>" without a scan of history the prune may have
        # already eaten.
        carried = previous.alarm_since if previous is not None and not is_transition else None
        alarm_since = carried or utcnow()

    # The reasons are stored as the plain strings they have always been: the
    # column, the audit payload and the webhook body are wire surfaces, and the
    # codes reach the UI as their own field (alarm_key) instead.
    messages = [r.message for r in reasons]
    await quality_store.insert_snapshot(
        db,
        mode=mode,
        n_ok=metrics.n_ok,
        n_error=metrics.n_error,
        agreement_rate=metrics.agreement_rate,
        fallback_rate=metrics.fallback_rate,
        error_rate=metrics.error_rate,
        verdict_counts=metrics.verdict_counts,
        latency_p50_ms=metrics.latency_p50_ms,
        batch_dir=batch_dir,
        alarmed=bool(reasons),
        alarm_reasons=messages or None,
        alarm_key=alarm_key,
        alarm_since=alarm_since,
        n_yes=metrics.n_yes,
        n_partial=metrics.n_partial,
        n_no=metrics.n_no,
        n_classified=metrics.n_classified,
    )
    return AlarmOutcome(
        reasons=messages,
        alarm_key=alarm_key,
        alarm_since=alarm_since,
        is_transition=is_transition,
    )


async def run_eval_nightly(
    settings: Any,
    *,
    mode: str | None = None,
    oql: str | None = None,
    out_dir: str | Path | None = None,
    per_run_timeout_s: int = 1800,
    emit: Callable[[str], None] | None = None,
    fire_alarm: Callable[..., Awaitable[None]] | None = None,
) -> NightlyRunResult:
    """Run one nightly quality micro-eval and persist its trend point.

    ``mode`` None follows the oracle posture (:func:`resolve_mode`); ``oql``
    None uses the web-UI alerts-feed query — the same population the dashboard
    shows; ``out_dir`` None lands the bundles beside the data dir
    (:func:`resolve_out_dir`). ``emit`` receives progress lines (the CLI colors
    them; the app logs them). ``fire_alarm`` fires regression side effects
    (audit + webhook) on a TRANSITION into a new condition only; None skips
    them entirely. Builds its own engine + Elastic client
    on purpose: the
    eval must be runnable before the app ever booted against this store
    (cron-first installs) and must not contend with the app's pools.
    """
    import functools  # noqa: PLC0415 - lazy: keep module import light

    from soc_ai.eval.batch import BatchConfig, run_batch  # noqa: PLC0415 - lazy
    from soc_ai.eval.harness import run as harness_run  # noqa: PLC0415 - lazy
    from soc_ai.eval.quality import compute_snapshot_metrics  # noqa: PLC0415 - lazy
    from soc_ai.eval.report import build_report, load_index  # noqa: PLC0415 - lazy
    from soc_ai.so_client.elastic import ElasticClient  # noqa: PLC0415 - lazy
    from soc_ai.store.db import (  # noqa: PLC0415 - lazy
        make_engine,
        make_sessionmaker,
        run_migrations,
    )

    def _emit(line: str) -> None:
        if emit is not None:
            emit(line)

    eval_mode = mode or resolve_mode(settings)
    # Clamp to the documented bounds even for env-sourced values: the config
    # console enforces [1,10] / [0.05,0.5], but a stray .env must not turn the
    # unattended nightly into an hour-long batch or a hair-trigger pager.
    n = max(1, min(10, settings.quality_nightly_n))
    alarm_drop = max(0.05, min(0.5, settings.quality_alarm_drop))
    eval_oql = oql or settings.webui_alerts_query
    bundle_dir, bundle_warning = resolve_out_dir(settings, out_dir)
    if bundle_warning is not None:
        _emit(bundle_warning)

    _emit(f"eval-nightly · mode={eval_mode} n={n} oql={eval_oql!r} out={bundle_dir}")

    cfg = BatchConfig(
        oql=eval_oql,
        n=n,
        # Concurrency 1: the nightly runs unattended on possibly-shared
        # inference infra — it must never contend with live triage.
        concurrency=1,
        out_dir=bundle_dir,
        per_run_timeout_s=per_run_timeout_s,
    )

    elastic = ElasticClient(settings)
    try:
        try:
            summary = await run_batch(
                cfg,
                settings=settings,
                elastic=elastic,
                # grade=False keeps the per-alert oracle call OUT of local
                # mode — the whole zero-egress contract hangs on this kwarg.
                runner=functools.partial(harness_run, grade=(eval_mode == "graded")),
                progress=_emit,
            )
        except RuntimeError as e:
            return NightlyRunResult(
                exit_code=EXIT_ERROR, mode=eval_mode, detail=f"eval-nightly failed: {e}"
            )
        except Exception as e:
            return NightlyRunResult(
                exit_code=EXIT_ERROR,
                mode=eval_mode,
                detail=f"eval-nightly failed (transport): {type(e).__name__}: {e}",
            )

        if summary.n_planned == 0:
            return NightlyRunResult(
                exit_code=EXIT_NO_ALERTS,
                mode=eval_mode,
                detail=f"no eligible alerts for {eval_oql!r} — no snapshot written",
            )
        if summary.aborted_reason:
            # Still record the point below: a fully-broken engine (every run
            # failing) is precisely the regression the trend exists to catch —
            # swallowing it would blind the alarm.
            _emit(summary.aborted_reason)

        # Aggregate (pure; no oracle, no meta-analysis) + reduce to a point.
        _json_path, _md_path, agg = build_report(summary.batch_dir)
        rows = load_index(summary.batch_dir)
        metrics = compute_snapshot_metrics(rows, agg, mode=eval_mode)

        # Trend: read same-mode history, detect, insert + prune in one txn.
        engine = make_engine(settings)
        try:
            # This may run before the app ever booted against this store
            # (fresh install, cron-first) — same idiom as
            # discover-internal-identifiers.
            await run_migrations(engine)
            maker = make_sessionmaker(engine)
            async with maker() as db:
                outcome = await _record_trend_point(
                    db,
                    metrics=metrics,
                    mode=eval_mode,
                    alarm_drop=alarm_drop,
                    batch_dir=str(summary.batch_dir),
                )
        finally:
            with contextlib.suppress(Exception):
                await engine.dispose()

        # Transition, not "alarmed": a condition that persists is one problem,
        # and paging once per run for it is what taught the operator to ignore
        # the card (prod rows 9/10/11). The row above recorded the alarm either
        # way, so nothing is lost — only repeated.
        if outcome.is_transition and fire_alarm is not None:
            await fire_alarm(
                settings,
                elastic=elastic,
                mode=eval_mode,
                reasons=outcome.reasons,
                metrics=metrics,
            )

        return NightlyRunResult(
            exit_code=EXIT_ABORTED if summary.aborted_reason else EXIT_OK,
            mode=eval_mode,
            metrics=metrics,
            batch_dir=str(summary.batch_dir),
            alarm_reasons=outcome.reasons or None,
            alarm_key=outcome.alarm_key,
            alarm_is_new=outcome.is_transition,
            detail=summary.aborted_reason or "",
        )
    finally:
        with contextlib.suppress(Exception):
            await elastic.aclose()
