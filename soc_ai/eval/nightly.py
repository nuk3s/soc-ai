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
"""

from __future__ import annotations

import contextlib
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

# Exit codes shared with the CLI (documented in `soc-ai eval-nightly --help`):
# 0 ok · 2 no eligible alerts (no snapshot) · 4 aborted-but-written · 5 error.
EXIT_OK = 0
EXIT_NO_ALERTS = 2
EXIT_ABORTED = 4
EXIT_ERROR = 5


@dataclass
class NightlyRunResult:
    exit_code: int
    mode: str
    # Set on any run that wrote a snapshot (exit 0 / 4); None on 2 / 5.
    metrics: Any | None = None
    batch_dir: str | None = None
    alarm_reasons: list[str] | None = None
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


async def run_eval_nightly(
    settings: Any,
    *,
    mode: str | None = None,
    oql: str | None = None,
    out_dir: str | Path = "evals",
    per_run_timeout_s: int = 1800,
    emit: Callable[[str], None] | None = None,
    fire_alarm: Callable[..., Awaitable[None]] | None = None,
) -> NightlyRunResult:
    """Run one nightly quality micro-eval and persist its trend point.

    ``mode`` None follows the oracle posture (:func:`resolve_mode`); ``oql``
    None uses the web-UI alerts-feed query — the same population the dashboard
    shows. ``emit`` receives progress lines (the CLI colors them; the app logs
    them). ``fire_alarm`` fires regression side effects (audit + webhook);
    None skips them. Builds its own engine + Elastic client on purpose: the
    eval must be runnable before the app ever booted against this store
    (cron-first installs) and must not contend with the app's pools.
    """
    import functools  # noqa: PLC0415 - lazy: keep module import light

    from soc_ai.eval.batch import BatchConfig, run_batch  # noqa: PLC0415 - lazy
    from soc_ai.eval.harness import run as harness_run  # noqa: PLC0415 - lazy
    from soc_ai.eval.quality import (  # noqa: PLC0415 - lazy
        TrendPoint,
        compute_snapshot_metrics,
        detect_regression,
    )
    from soc_ai.eval.report import build_report, load_index  # noqa: PLC0415 - lazy
    from soc_ai.so_client.elastic import ElasticClient  # noqa: PLC0415 - lazy
    from soc_ai.store import quality as quality_store  # noqa: PLC0415 - lazy
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

    _emit(f"eval-nightly · mode={eval_mode} n={n} oql={eval_oql!r}")

    cfg = BatchConfig(
        oql=eval_oql,
        n=n,
        # Concurrency 1: the nightly runs unattended on possibly-shared
        # inference infra — it must never contend with live triage.
        concurrency=1,
        out_dir=Path(out_dir),
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
                history = await quality_store.recent_snapshots(db, limit=7, mode=eval_mode)
                reasons = detect_regression(
                    metrics,
                    [
                        TrendPoint(
                            agreement_rate=h.agreement_rate,
                            fallback_rate=h.fallback_rate,
                        )
                        for h in history
                    ],
                    alarm_drop=alarm_drop,
                )
                await quality_store.insert_snapshot(
                    db,
                    mode=eval_mode,
                    n_ok=metrics.n_ok,
                    n_error=metrics.n_error,
                    agreement_rate=metrics.agreement_rate,
                    fallback_rate=metrics.fallback_rate,
                    error_rate=metrics.error_rate,
                    verdict_counts=metrics.verdict_counts,
                    latency_p50_ms=metrics.latency_p50_ms,
                    batch_dir=str(summary.batch_dir),
                    alarmed=bool(reasons),
                    alarm_reasons=reasons or None,
                )
        finally:
            with contextlib.suppress(Exception):
                await engine.dispose()

        if reasons and fire_alarm is not None:
            await fire_alarm(
                settings, elastic=elastic, mode=eval_mode, reasons=reasons, metrics=metrics
            )

        return NightlyRunResult(
            exit_code=EXIT_ABORTED if summary.aborted_reason else EXIT_OK,
            mode=eval_mode,
            metrics=metrics,
            batch_dir=str(summary.batch_dir),
            alarm_reasons=reasons or None,
            detail=summary.aborted_reason or "",
        )
    finally:
        with contextlib.suppress(Exception):
            await elastic.aclose()
