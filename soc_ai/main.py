"""FastAPI application entry point.

``uv run soc-ai`` boots the API via :func:`main`; ``uvicorn soc_ai.main:app``
boots it directly. The lifespan manager constructs every long-lived dependency
once and tears them down on shutdown.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import os
import re
import time
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from fastapi import FastAPI, Request
from fastapi.encoders import jsonable_encoder
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.responses import JSONResponse, RedirectResponse, Response
from starlette.types import Scope

from soc_ai import __version__
from soc_ai.agent.orchestrator import build_local_enrichment_context
from soc_ai.api.routes import router
from soc_ai.api.webui_api import open_router as api_v1_open_router
from soc_ai.api.webui_api import router as api_v1_router
from soc_ai.audit.logger import AuditLogger
from soc_ai.bootstrap_credential import bootstrap_credential_path
from soc_ai.config import get_settings
from soc_ai.hunting.window import sweep_window
from soc_ai.so_client.auth import make_auth
from soc_ai.so_client.elastic import ElasticClient
from soc_ai.store import backtests as bt_svc
from soc_ai.store import chat as chat_svc
from soc_ai.store import general_chat as general_chat_svc
from soc_ai.store import hunt_templates as hunt_templates_svc
from soc_ai.store import hunts as hunt_svc
from soc_ai.store import investigations as inv_svc
from soc_ai.store import leads as leads_store
from soc_ai.store.auth import bootstrap_admin, purge_expired_sessions
from soc_ai.store.config_overrides import apply_to_settings, load_overrides
from soc_ai.store.db import make_engine, make_sessionmaker, run_migrations
from soc_ai.store.secret_box import make_secret_box
from soc_ai.tools.enrichment import MispClient

_LOGGER = logging.getLogger(__name__)

# The built React SPA. Shipped to the deploy target alongside the package; absent
# in source checkouts until `npm run build` runs, so serving is best-effort.
FRONTEND_DIST = Path(__file__).resolve().parent.parent / "frontend" / "dist"


class SpaStaticFiles(StaticFiles):
    """StaticFiles that falls back to index.html on 404 so client-side
    (BrowserRouter) deep links like /app/investigation/INV-1 resolve.

    index.html is additionally served ``Cache-Control: no-cache`` (revalidate
    every load — NOT "don't cache"): a deploy replaces the content-hashed
    ``/assets/*`` files, so a browser reusing a stale cached index.html points
    at chunk filenames that no longer exist and the SPA dynamic-imports 404
    until a hard refresh. The hashed assets themselves keep StaticFiles'
    default ETag/Last-Modified caching.
    """

    async def get_response(self, path: str, scope: Scope) -> Response:
        try:
            return await super().get_response(path, scope)
        except StarletteHTTPException as exc:
            if exc.status_code == 404:
                return await super().get_response("index.html", scope)
            raise

    def file_response(
        self,
        full_path: str | os.PathLike[str],
        stat_result: os.stat_result,
        scope: Scope,
        status_code: int = 200,
    ) -> Response:
        # Every path that ends up serving index.html funnels through here: the
        # direct file, the html-mode directory root (/app/), and the SPA
        # fallback above. Setting the header on the returned response also
        # covers the 304 NotModifiedResponse branch (revalidation replies must
        # keep carrying the policy so clients don't regress to heuristics).
        response = super().file_response(full_path, stat_result, scope, status_code)
        if Path(full_path).name == "index.html":
            response.headers["Cache-Control"] = "no-cache"
        return response


async def _reaper_loop(db_sessionmaker: Any, settings: Any) -> None:
    """Periodically mark stale ``running`` investigations + ``pending`` chat
    turns as ``error``.

    Runs until cancelled at shutdown. A failed iteration is logged and the loop
    continues — the reaper must never take the app down. Disabled (no-op loop)
    when either investigation knob is <= 0.

    The chat sweeps ride the same cadence: they mark ``pending`` assistant rows
    older than ``chat_turn_timeout_s`` as ``error`` (a turn still inside its
    timeout is legitimately in flight and is spared). They are a backstop for the
    in-process timeout/cancel handlers — they catch a turn whose handlers never
    ran (e.g. a wedged event loop) or a row a transient DB error left pending.

    Investigation chat and dashboard (general) chat are separate tables with
    separate reapers, swept in separate try blocks: neither store's sweep may be
    skipped because the other one raised, since a table that goes unswept has no
    symptom until an analyst is looking at a turn that will never finish.
    """
    interval_min = settings.investigation_reaper_interval_minutes
    age_min = settings.investigation_reaper_minutes
    if interval_min <= 0 or age_min <= 0:
        return
    chat_age = timedelta(seconds=max(int(getattr(settings, "chat_turn_timeout_s", 180)), 1))
    # Backtests and hunts legitimately run FAR longer than a single investigation,
    # so reaping them at the investigation age (default 30 min) flips an in-flight
    # job to 'error' mid-run. Derive each its own reap age from its real ceiling:
    #   * a backtest replays up to ``backtest_max_sample`` full investigations
    #     back-to-back, each bounded by ``investigation_run_timeout_s`` — worst-case
    #     budget is the product. Every backtest is clamped to that sample cap, so
    #     this age never reaps a legitimately-running one regardless of sample size.
    #   * a hunt runs to its ``hunt_run_timeout_s`` wall-clock backstop and then
    #     does partial synthesis — budget that plus a synthesis margin (one age_min).
    # ``max(age_min, …)`` keeps each at least as generous as the investigation knob.
    inv_run_min = max(int(getattr(settings, "investigation_run_timeout_s", 900)) // 60, 1)
    hunt_age_min = max(age_min, int(getattr(settings, "hunt_run_timeout_s", 1800)) // 60 + age_min)
    bt_age_min = max(
        age_min, int(getattr(settings, "backtest_max_sample", 50)) * inv_run_min + age_min
    )
    while True:
        await asyncio.sleep(interval_min * 60)
        try:
            async with db_sessionmaker() as db:
                n = await inv_svc.reap_stale_running(db, older_than_minutes=age_min)
            if n:
                _LOGGER.info("reaper: marked %d stale 'running' investigation(s) as error", n)
            async with db_sessionmaker() as db:
                nh = await hunt_svc.reap_stale_running(db, older_than_minutes=hunt_age_min)
            if nh:
                _LOGGER.info("reaper: marked %d stale 'running' hunt(s) as error", nh)
            async with db_sessionmaker() as db:
                nb = await bt_svc.reap_stale_running(db, older_than_minutes=bt_age_min)
            if nb:
                _LOGGER.info("reaper: marked %d stale 'running' backtest(s) as error", nb)
        except asyncio.CancelledError:
            raise
        except Exception:
            _LOGGER.exception("investigation reaper iteration failed; continuing")
        try:
            async with db_sessionmaker() as db:
                nc = await chat_svc.reap_stale_pending(db, older_than=chat_age)
            if nc:
                _LOGGER.info("reaper: marked %d stale 'pending' chat turn(s) as error", nc)
        except asyncio.CancelledError:
            raise
        except Exception:
            _LOGGER.exception("chat reaper iteration failed; continuing")
        try:
            async with db_sessionmaker() as db:
                ng = await general_chat_svc.reap_stale_pending(db, older_than=chat_age)
            if ng:
                _LOGGER.info(
                    "reaper: marked %d stale 'pending' dashboard chat turn(s) as error", ng
                )
        except asyncio.CancelledError:
            raise
        except Exception:
            _LOGGER.exception("dashboard chat reaper iteration failed; continuing")


def _discovery_due(last_scan_iso: str | None, interval_hours: int) -> bool:
    """True iff a scheduled discovery scan is due.

    Due when there has been no scan this process (`last_scan_iso is None`) or at
    least `interval_hours` have elapsed since the last completed scan. A bad/
    unparseable timestamp is treated as 'due' (fail toward running the scan).
    """
    if last_scan_iso is None:
        return True
    try:
        last = datetime.fromisoformat(last_scan_iso)
    except ValueError:
        return True
    return (datetime.now(UTC) - last) >= timedelta(hours=interval_hours)


def _dossier_due(last_run_iso: str | None, interval_hours: int) -> bool:
    """True iff a scheduled host-dossier sweep is due.

    The elapsed-time maths is :func:`_discovery_due`'s; what differs is where
    ``last_run_iso`` comes from. It is the newest ``dossier_run.started_at`` —
    a DURABLE stamp — not an ``app.state`` field. An in-memory stamp is ``None``
    on every boot and ``None`` reads as due, so a crash-restart loop would
    re-sweep the whole network (hundreds of hosts, several ES round trips each) on
    each boot. Read from the run table, ``None`` means "no sweep has ever
    started", which genuinely is due.
    """
    return _discovery_due(last_run_iso, interval_hours)


def _audit_verify_due(last_run_iso: str | None, interval_hours: int) -> bool:
    """True iff a scheduled audit-chain verification is due.

    :func:`_discovery_due`'s elapsed-time maths against an ``app.state`` stamp.
    In-memory on purpose, unlike the dossier's durable stamp: a restart
    re-verifying is a bounded read of one index, and the failure this schedule
    exists to catch is precisely the kind that hides behind "we already
    checked".
    """
    return _discovery_due(last_run_iso, interval_hours)


def _eval_nightly_due(
    now: datetime,
    *,
    hour_utc: int,
    last_scheduled_date: str | None,
    latest_snapshot_date: str | None,
    last_attempt_date: str | None = None,
) -> bool:
    """True iff the in-app nightly quality eval should run at *now*.

    Runs at most once per UTC day, at the first wake at/after ``hour_utc``.
    Three once-per-day guards, and each covers a case the others do not:

    * ``last_scheduled_date`` — in memory, claimed the instant this process
      schedules a run, so two wakes a few minutes apart cannot both fire.
    * ``latest_snapshot_date`` — durable, and covers a restart after a run
      that WROTE a point, plus a host-cron run that already landed today's.
    * ``last_attempt_date`` — durable, and covers the gap between those two:
      an exit-2 or exit-5 night writes no snapshot, so before this table the
      only guard on a night the nightly failed was the in-memory one, and a
      restart loop could re-run it repeatedly on exactly the nights something
      was already wrong.
    """
    today = now.date().isoformat()
    if last_scheduled_date == today:
        return False
    if last_attempt_date == today:
        return False
    if now.hour < hour_utc:
        return False
    return latest_snapshot_date != today


async def _hunt_spec_sweep_loop(app: FastAPI) -> None:
    """Run the declarative hunt catalog on a loop (proactive-hunting slice 3).

    The seventh lifespan task, and the one with the least in it: a sweep costs
    no model call at all. It compiles each spec to two bounded Elasticsearch
    queries, drops every condition the fire-once gate has already handled, and
    records what survives as a ``Hunt(kind="triggered")``. Nothing generative
    runs, so a finding from this path cannot hallucinate.

    Mirrors :func:`_hunt_schedule_loop`'s discipline — fixed 60s wake, settings
    read live each wake so a config-console toggle applies without a restart,
    a no-op unless ``hunt_spec_sweeps_enabled`` — and differs in three ways
    that follow from costing nothing:

    - the interval floor is 5 minutes rather than 60, because two aggregations
      per spec is not an LLM hunt;
    - the LOOK-BACK window is wider than the interval (24h by default), so a
      condition that landed during an outage, a restart or an ingest lag is
      still seen. That overlap is deliberate and is exactly what a live-tailing
      rule engine cannot do — the fire-once gate is what stops it becoming
      repeat findings;
    - there is no per-spec schedule row, so the single-flight is a module-level
      guard on the whole sweep rather than per-item state.

    A spec that fails is reported inside :func:`sweep_catalog` and never stops
    the rest of the catalog. A sweep that fails as a whole is logged and the
    loop continues; the next wake re-reads a fresh window.

    Note (workers>1): a second uvicorn worker would run its own copy and double
    the query load. The gate's unique constraint means it could not double the
    FINDINGS, which is the part that matters, but soc-ai runs a single worker
    today and distributed coordination is Epoch 6.2, as for the loop above.
    """
    from soc_ai.hunting.catalog_tiers import effective_catalog  # noqa: PLC0415
    from soc_ai.hunting.sweep import sweep_catalog  # noqa: PLC0415

    last_run: datetime | None = None

    while True:
        await asyncio.sleep(60)
        try:
            settings = app.state.settings
            if not getattr(settings, "hunt_spec_sweeps_enabled", False):
                continue
            # The floor and the clamp live in soc_ai.hunting.window, shared
            # with `soc-ai spec-sweep` and the catalog route, so a hand-run
            # sweep covers exactly what this loop covers and the panel reports
            # the same number the trail rows record.
            window = sweep_window(settings)
            now = datetime.now(UTC).replace(tzinfo=None)
            if last_run is not None and (now - last_run) < timedelta(
                minutes=window.interval_minutes
            ):
                continue

            # Said once per sweep, after the interval check, so a
            # misconfiguration is visible without being repeated every wake.
            window.say_if_widened(_LOGGER)
            # The effective catalog, not the files alone: a retired analytic
            # must stop running and a local one in shadow must start, and both
            # facts live in the database.
            async with app.state.db_sessionmaker() as db:
                tiers = await effective_catalog(db)
            catalog = tiers.specs
            if not catalog:
                continue

            async with app.state.db_sessionmaker() as db:
                result = await sweep_catalog(
                    catalog,
                    session=db,
                    elastic=app.state.elastic,
                    settings=settings,
                    since=window.since,
                    until="now",
                    now=now,
                    shadow_ids=tiers.shadow_ids,
                )
                await db.commit()
            # Stamped only after a completed sweep, so a crash mid-sweep retries
            # on the next wake rather than skipping a whole interval.
            last_run = now

            if result.hunts or result.blind or result.errored or result.gaps_cleared:
                _LOGGER.info(
                    "spec sweep: %d hunt(s) from %d fresh candidate(s); "
                    "%d already handled, %d blind, %d errored",
                    len(result.hunts),
                    result.fresh_candidates,
                    result.already_handled,
                    len(result.blind),
                    len(result.errored),
                )
            # Its own line, and its own condition rather than a clause on the
            # summary above: a sweep whose only news is a recovery has no
            # hunts, nothing blind and nothing errored, so before this the
            # summary did not fire for it and an outage ENDING was the quietest
            # event in the log. INFO, not WARNING — the transition the other
            # way is reported at INFO too, and a "things are better now" line
            # at WARNING is one anybody alerting on the level would misread.
            if result.gaps_cleared:
                _LOGGER.info(
                    "spec sweep: %d spec(s) can see their telemetry again; "
                    "the visibility gap recorded for them is closed",
                    result.gaps_cleared,
                )
            for spec_id, err in result.errored.items():
                _LOGGER.warning("spec sweep: %s failed against the grid: %s", spec_id, err)
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            _LOGGER.warning("spec sweep loop: %s: %s", type(exc).__name__, exc)


# The shortest interval the profile sweep will accept. A sweep makes no model
# call, so the floor is far below the hour an LLM schedule needs. It is not
# zero: each sweep is several real aggregations per dimension against the
# analyst's grid.
PRIOR_SWEEP_MIN_INTERVAL_MINUTES = 15


def _prior_sweep_interval_minutes(settings: Any) -> int:
    """Minutes between profile sweeps, with the floor applied.

    The console bounds the setting, and this bounds it again. An override
    written before the bound existed, or a settings object built in code,
    reaches the loop without passing the console at all.
    """
    raw = getattr(settings, "hunting_prior_sweep_interval_minutes", 60)
    try:
        minutes = int(raw or 0)
    except (TypeError, ValueError):
        minutes = 0
    return max(PRIOR_SWEEP_MIN_INTERVAL_MINUTES, minutes)


def _grid_is_known_down(app: FastAPI) -> bool:
    """Has the health probe loop seen Elasticsearch fail and not recover?

    Reads the map ``_note_dep_transitions`` keeps on ``app.state``, so the
    answer costs no query. Unknown reads as up: a process that has not probed
    yet must sweep rather than wait.
    """
    down = getattr(app.state, "_dep_down_since", None) or {}
    return "es" in down


def _profile_stale_after(settings: Any) -> timedelta:
    """How old a baseline may be before the prior sweep rebuilds it.

    The dossier interval, floored at two prior-sweep intervals. A rebuild on
    every wake would double the query load for baselines that change on the
    timescale of a provisioning ticket, not a shift.
    """
    try:
        hours = int(getattr(settings, "dossier_schedule_interval_hours", 24) or 24)
    except (TypeError, ValueError):
        hours = 24
    floor = 2 * _prior_sweep_interval_minutes(settings)
    return timedelta(minutes=max(hours * 60, floor))


def _profiles_are_stale(newest: datetime | None, now: datetime, threshold: timedelta) -> bool:
    """Never built, older than the threshold, or stamped in the future.

    The future case is a row written in local time east of UTC by the release
    that stamped ``datetime.now()``. Rebuilding it is what ends the skew; no
    migration can, because no migration knows the host's offset.
    """
    if newest is None:
        return True
    return newest > now or (now - newest) >= threshold


def _profile_age(newest: datetime | None, now: datetime) -> str:
    if newest is None:
        return "never built"
    hours = max(0, int((now - newest).total_seconds() // 3600))
    return f"{hours} h old"


def _unmeasurable_reason(unmeasurable: dict[str, str]) -> str | None:
    joined = "; ".join(f"{d}: {r}" for d, r in sorted(unmeasurable.items()))
    return joined[:255] or None


async def _refresh_profiles_if_stale(app: FastAPI, settings: Any, now: datetime) -> Any:
    """Rebuild the baselines the sweep is about to read, when they are stale.

    Returns the ``ProfileState`` the sweep records, or ``None`` when profiles
    are off. Runs whether or not the dossier schedule is on: the sweep is the
    only consumer of the baselines, so it owns their freshness. The rebuild
    takes the dossier's single-flight slot, because two network sweeps at once
    is the connection-pool pressure that has frozen this app before; if the
    slot is held the rebuild waits for the next wake.

    Never raises. A rebuild that fails is logged and the sweep runs on what
    exists, reporting it stale.
    """
    from soc_ai.api.webui import _get_dossier_status  # noqa: PLC0415
    from soc_ai.dossier import profile_job  # noqa: PLC0415
    from soc_ai.hunting.prior_sweep import ProfileState  # noqa: PLC0415
    from soc_ai.oracle.identifiers import effective_internal_identifiers  # noqa: PLC0415

    if not getattr(settings, "entity_profiles_enabled", False):
        return None

    before = await profile_job.freshness(app.state.db_sessionmaker)
    age = _profile_age(before.newest_built_at, now)
    reason = _unmeasurable_reason(before.unmeasurable)
    if not _profiles_are_stale(before.newest_built_at, now, _profile_stale_after(settings)):
        _LOGGER.info("prior sweep: profiles %s", age)
        return ProfileState(built_at=before.newest_built_at, stale=False, reason=reason)

    status = _get_dossier_status(app.state)
    if status.running:
        _LOGGER.info(
            "prior sweep: profiles %s; a dossier sweep holds the slot, rebuild skipped this wake",
            age,
        )
        return ProfileState(built_at=before.newest_built_at, stale=True, reason=reason)

    status.running = True
    try:
        async with app.state.db_sessionmaker() as db:
            cidrs = (await effective_internal_identifiers(db, settings)).cidrs
        build = await profile_job.build_profiles(
            app.state.elastic, app.state.db_sessionmaker, settings, cidrs
        )
    except Exception as exc:
        _LOGGER.warning("prior sweep: profile rebuild failed: %s: %s", type(exc).__name__, exc)
        return ProfileState(built_at=before.newest_built_at, stale=True, reason=reason)
    finally:
        status.running = False

    for err in build.errors:
        _LOGGER.warning("prior sweep: %s", err)
    after = await profile_job.freshness(app.state.db_sessionmaker)
    _LOGGER.info("prior sweep: profiles %s, rebuilt %d row(s)", age, build.written)
    return ProfileState(
        built_at=after.newest_built_at,
        stale=False,
        reason=_unmeasurable_reason(after.unmeasurable),
    )


async def _prior_sweep_loop(app: FastAPI) -> None:
    """Run the profile sweep on a loop: the hunting layer's supply of observations.

    This is the code path ``soc-ai priors --record`` runs. The test range runs
    it from a host timer every hour. A container has no timer, so before this
    loop a production deployment shipped the profile layer and never ran it:
    no observation was recorded, no profile lead formed, and every surface
    stayed green. A job nobody scheduled is the same false all-clear as a
    surface that lies, arrived at from the supply side.

    Mirrors :func:`_hunt_spec_sweep_loop`'s discipline — fixed 60 s wake,
    settings read live each wake so a config-console toggle applies without a
    restart, an interval floor, one line in the log per run — and differs in
    three ways:

    - it is ON by default. A catalog sweep writes findings, so it is opt-in. A
      profile sweep writes observations and raises nothing, and a deployment
      with no profile observation has no hunting layer;
    - it skips a demo and a grid the health probe already knows is down. Both
      write the same damage: a sweep that could not measure records that
      nothing departed, which is a baseline learning from an outage;
    - it owns the freshness of the baselines it reads. If profiles are on and
      the newest is missing, older than the dossier interval (floored at two
      sweep intervals) or stamped in the future, it rebuilds them first, under
      the dossier's single-flight slot, whatever the dossier schedule says. A
      rebuild that fails is logged and the sweep runs on what exists.

    The sweep itself never raises: it returns its errors, and they are logged
    beside the counts. A sweep that fails another way is logged and the loop
    continues; the last-run stamp is written only after a sweep that returned,
    so a failure retries on the next wake rather than costing a whole interval.

    Note (workers>1): a second uvicorn worker would run its own copy and
    double the query load. soc-ai runs a single worker today and distributed
    coordination is Epoch 6.2, as for the loops above.
    """
    from soc_ai.hunting.catalog_tiers import effective_catalog  # noqa: PLC0415
    from soc_ai.hunting.prior_sweep import run_prior_sweep  # noqa: PLC0415
    from soc_ai.hunting.priors import COVERAGE_BLIND  # noqa: PLC0415
    from soc_ai.oracle.identifiers import effective_internal_identifiers  # noqa: PLC0415

    app.state.prior_sweep_last_run = None

    while True:
        await asyncio.sleep(60)
        try:
            settings = app.state.settings
            if not getattr(settings, "hunting_prior_sweep_enabled", True):
                continue
            if getattr(settings, "soc_ai_demo", False):
                continue
            if _grid_is_known_down(app):
                continue

            now = datetime.now(UTC).replace(tzinfo=None)
            last_run = getattr(app.state, "prior_sweep_last_run", None)
            if last_run is not None and (now - last_run) < timedelta(
                minutes=_prior_sweep_interval_minutes(settings)
            ):
                continue

            # The baselines first. The sweep reads them, so their freshness
            # is the sweep's job, not a second schedule's.
            profiles = await _refresh_profiles_if_stale(app, settings, now)

            async with app.state.db_sessionmaker() as db:
                # The estate's own address space, so the sweep does not record
                # observations about the internet and form leads out of them.
                cidrs = (await effective_internal_identifiers(db, settings)).cidrs
                # The effective catalog, for the same reason the spec sweep
                # reads it: a retired prior must stop running and a local one
                # in shadow must start.
                tiers = await effective_catalog(db)
                sweep = await run_prior_sweep(
                    elastic=app.state.elastic,
                    settings=settings,
                    db=db,
                    record=True,
                    cidrs=cidrs,
                    catalog=tiers.specs,
                    shadow_ids=tiers.shadow_ids,
                    profiles=profiles,
                )
                await db.commit()
            # Stamped only after a sweep that returned, so a failure retries on
            # the next wake rather than skipping the whole interval.
            app.state.prior_sweep_last_run = now

            observations = sum(len(r.departures) for r in sweep.results)
            leads = len(sweep.leads.formed) if sweep.leads is not None else 0
            blind = sweep.coverage_counts().get(COVERAGE_BLIND, 0)
            # Said every run, not only when something departed. A quiet sweep
            # is how an operator knows the loop is alive, and the blind count
            # is what separates "nothing departed" from "nothing could be
            # measured" — the same empty list, and completely different news.
            _LOGGER.info(
                "prior sweep: %d observation(s), %d lead(s), %d blind",
                observations,
                leads,
                blind,
            )
            for err in sweep.errors:
                _LOGGER.warning("prior sweep: %s", err)
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            _LOGGER.warning("prior sweep loop: %s: %s", type(exc).__name__, exc)


async def _eval_nightly_loop(app: FastAPI, settings: Any) -> None:
    """Run the nightly quality micro-eval in-app when scheduled.

    The nightly used to be host-cron-only; ``eval_nightly_enabled`` makes it
    schedulable from the UI (Config → Quality). Models the discovery loop:
    fixed wake cadence, live settings read each wake (console toggles apply
    without a restart), and the run-now single-flight ``_QualityEvalStatus``
    shared with POST /quality/eval/run so a scheduled run and a manual run
    can never overlap. A failed iteration is logged and the loop continues.
    """
    # Lazy import: reuse the run-now single-flight + worker (one direction).
    from soc_ai.api.webui_api import (  # noqa: PLC0415
        _get_quality_eval_status,
        _quality_eval_worker,
    )

    wake_seconds = 300
    while True:
        await asyncio.sleep(wake_seconds)
        try:
            if not settings.eval_nightly_enabled:
                continue
            status = _get_quality_eval_status(app.state)
            if status.running:
                continue
            now = datetime.now(UTC)
            # Durable freshness check — fail-soft toward "no snapshot today"
            # (running twice is cheaper than silently never running).
            latest_snapshot_date: str | None = None
            last_attempt_date: str | None = None
            try:
                from soc_ai.store import quality as quality_store  # noqa: PLC0415

                async with app.state.db_sessionmaker() as db:
                    rows = await quality_store.recent_snapshots(db, limit=1)
                    attempt = await quality_store.latest_attempt(db)
                if rows:
                    latest_snapshot_date = rows[0].created_at.date().isoformat()
                if attempt is not None:
                    last_attempt_date = attempt.attempted_at.date().isoformat()
            except Exception:
                _LOGGER.warning(
                    "eval-nightly: snapshot freshness check failed (continuing)", exc_info=True
                )
            if not _eval_nightly_due(
                now,
                hour_utc=settings.eval_nightly_hour_utc,
                last_scheduled_date=status.last_scheduled_date,
                latest_snapshot_date=latest_snapshot_date,
                last_attempt_date=last_attempt_date,
            ):
                # A point already landed today (host cron / pre-restart run):
                # consume the day so later wakes skip the DB check too.
                if latest_snapshot_date == now.date().isoformat():
                    status.last_scheduled_date = latest_snapshot_date
                continue
            status.last_scheduled_date = now.date().isoformat()
            status.running = True  # claim the single-flight slot before scheduling
            status._task = asyncio.create_task(_quality_eval_worker(app.state, trigger="schedule"))
        except asyncio.CancelledError:
            raise
        except Exception:
            _LOGGER.exception("eval-nightly scheduler iteration failed; continuing")


async def _health_probe_loop(app: FastAPI, settings: Any) -> None:
    """Probe the upstreams on a schedule, so an outage is noticed with no tab open.

    Every health surface in this app is pull-only behind a TTL cache, and
    ``_note_dep_transitions`` — the code that records when a dependency went
    down, and the only thing that puts a dependency-down entry on the bell —
    runs solely as a side effect of a client polling ``/api/v1/health``.

    So an open browser tab was the scheduler. Elasticsearch could be down all
    night, come back before anyone looked, and nothing anywhere would know it
    had happened: no bell entry, no transition recorded, no log. That is the
    same false-quiet this codebase keeps finding, arrived at from the other
    direction — not a surface that lies, a surface nobody asked.

    Cheap by construction. It calls the same cached probe the endpoint does, so
    a wake inside the TTL costs nothing and a polling client and this loop share
    one result rather than doubling the load. PCAP is deliberately not probed:
    it is a heavy SSH round trip on a much longer TTL and nothing on the bell
    keys on it.
    """
    from soc_ai.api.webui.routes_meta import _cached_health_probes  # noqa: PLC0415 - lazy

    wake_seconds = 60
    while True:
        await asyncio.sleep(wake_seconds)
        try:
            await _cached_health_probes(app.state, settings)
        except Exception:
            # A probe that could not run is not a dependency being down, and
            # must not be recorded as one. probe_* never raise; this guards the
            # loop against anything else so a single bad wake cannot kill the
            # only scheduled health check in the process.
            _LOGGER.warning("scheduled health probe failed to run", exc_info=True)


async def _audit_verify_loop(app: FastAPI, settings: Any) -> None:
    """Periodically verify the tamper-evident audit chain, and alarm on a break.

    A tamper-evident log nobody verifies is a log. The chain has been
    checkable since v1 — ``soc-ai audit verify``, and the admin verify-chain
    diagnostic — and in practice nothing ever ran either, so a live deployment
    carried a broken current epoch for weeks with nothing saying so. This loop
    is the thing that says so.

    Models :func:`_discovery_scheduler_loop`: fixed wake, live settings read
    each wake so a console toggle applies without a restart, and a failed
    iteration logged and swallowed. The scan runs inline rather than in a
    spawned task — it is a bounded ES read, not a model run — so the loop
    cannot overlap itself and needs no single-flight slot.

    Three outcomes, three different responses:

    - broken — an audit record (kind ``audit_chain_verification``, into the
      very chain it is reporting on) plus the opt-in notification webhook plus
      a standing entry on the in-app bell. Same two channels the nightly
      quality regression uses, and the bell besides, because notifications are
      off by default and a tamper finding that reaches nobody on a default
      install is the failure this loop exists to end.
    - intact — nothing is sent and any standing alarm is cleared, so the bell
      entry disappears on its own once the trail is sound again.
    - could not run (unreachable or half-read index) — logged, never alarmed.
      A verification that did not happen is not a tamper finding, and treating
      it as one would teach the operator to ignore the alarm that matters.

    Until a fix lands for whatever is breaking the chain, this reports the
    break on every run. That is the honest state; it is not suppressed.
    """
    from soc_ai import notify  # noqa: PLC0415 - lazy
    from soc_ai.api.webui.routes_config import _get_audit_verify_status  # noqa: PLC0415
    from soc_ai.audit.verify import verify_audit_chain  # noqa: PLC0415

    wake_seconds = 300
    while True:
        await asyncio.sleep(wake_seconds)
        try:
            # Re-read every wake → console toggle / interval edits apply live.
            if not settings.audit_verify_schedule_enabled:
                continue
            status = _get_audit_verify_status(app.state)
            if not _audit_verify_due(
                status.last_run, settings.audit_verify_schedule_interval_hours
            ):
                continue
            elastic = getattr(app.state, "elastic", None)
            if elastic is None:
                continue
            days = max(1, int(settings.audit_verify_days))
            try:
                result = await verify_audit_chain(elastic, settings.audit_index_alias, days=days)
            except Exception:
                # Could not run. NOT a tamper finding — see the docstring.
                _LOGGER.warning(
                    "scheduled audit-chain verification could not run (the audit "
                    "index was unreachable or only partly readable); no verdict "
                    "either way",
                    exc_info=True,
                )
                status.last_run = datetime.now(UTC).isoformat()
                continue
            status.last_run = datetime.now(UTC).isoformat()
            if result.ok:
                status.alarm = None
                _LOGGER.info(
                    "audit chain verified: %d records, %d epoch(s), last %dd",
                    result.records_verified,
                    result.epochs,
                    days,
                )
                continue
            await _raise_audit_chain_alarm(app, settings, result, status, days, notify)
        except asyncio.CancelledError:
            raise
        except Exception:
            _LOGGER.exception("audit chain verification scheduler iteration failed; continuing")


async def _raise_audit_chain_alarm(
    app: FastAPI,
    settings: Any,
    result: Any,
    status: Any,
    days: int,
    notify: Any,
) -> None:
    """Put one chain-break finding in front of a human, three ways.

    Split out of the loop so each channel's failure is contained: the bell
    entry is set first and from memory, so it survives an audit index that
    cannot take the record and a webhook that will not answer.

    Every channel carries the blast radius, not one sequence number out of
    however many broke, and the bell entry carries an identity for the FINDING
    rather than for the moment it was noticed, so a standing alarm can be
    dismissed without a new break inheriting the dismissal. See
    :func:`~soc_ai.audit.verify.finding_key` for what that identity is made of
    and :func:`~soc_ai.audit.verify.finding_is_dismissible` for the one kind of
    finding that is never offered as dismissible.
    """
    from soc_ai.audit.verify import (  # noqa: PLC0415 - lazy
        describe_blast_radius,
        finding_is_dismissible,
        finding_key,
    )

    blast_radius = describe_blast_radius(result)
    payload: dict[str, Any] = {
        "window_days": days,
        "records_verified": result.records_verified,
        "epochs": result.epochs,
        "epochs_broken": result.epochs_broken,
        "latest_epoch_broken": result.latest_epoch_broken,
        "capped": result.capped,
        "break_kind": result.newest_break_kind,
        "break_seq": result.first_broken_seq,
        "break_detail": result.newest_break_detail,
        "newest_broken_epoch_start": result.newest_broken_epoch_start,
        "break_kinds": list(result.break_kinds),
        "duplicate_seqs": result.duplicate_seqs,
        "extra_records": result.extra_records,
        "max_claimants": result.max_claimants,
        "altered_records": result.altered_records,
        "missing_seqs": result.missing_seqs,
        "oldest_break_at": result.oldest_break_at,
        "newest_break_at": result.newest_break_at,
        "blast_radius": blast_radius,
    }
    now = datetime.now(UTC).isoformat()
    key = finding_key(result)
    previous = status.alarm if isinstance(status.alarm, dict) else None
    # The clock the bell renders is when THIS finding was first seen, not when
    # it was last looked at, so a standing scar does not read as "just now"
    # every morning.
    since = previous.get("alarm_since") if previous and previous.get("alarm_key") == key else None
    status.alarm = dict(
        payload,
        detected_at=now,
        alarm_key=key,
        alarm_since=since or now,
        dismissible=finding_is_dismissible(result),
    )
    _LOGGER.error(
        "AUDIT CHAIN BROKEN: %s (%d of %d epochs, last %dd)",
        blast_radius or result.newest_break_detail or "the chain does not verify",
        result.epochs_broken,
        result.epochs,
        days,
    )
    audit = getattr(app.state, "audit", None)
    if audit is not None:
        try:
            await audit.log_kind(
                session_id="audit-chain-verify",
                kind="audit_chain_verification",
                payload=payload,
            )
        except Exception:
            _LOGGER.warning("audit-chain-break record could not be written", exc_info=True)
    event = notify.event_for_audit_chain_break(
        epochs_broken=result.epochs_broken,
        seq=result.first_broken_seq,
        kind=result.newest_break_kind,
        detail=result.newest_break_detail,
        latest_epoch_broken=result.latest_epoch_broken,
        settings=settings,
        blast_radius=blast_radius,
    )
    if event is not None:
        await notify.fire_safe(event, settings, audit)


async def _discovery_scheduler_loop(app: FastAPI, settings: Any) -> None:
    """Periodically run the internal-identifier discovery scan when scheduled.

    Runs until cancelled at shutdown. Models `_reaper_loop`: wake on a fixed
    cadence, read the live settings each wake (so a config-console toggle takes
    effect without a restart), and no-op unless scheduling is enabled. Shares the
    scan-now single-flight `_DiscoveryStatus` on `app.state`, so a scheduled run
    and a manual 'Scan now' can never overlap. A failed iteration is logged and
    the loop continues — the scheduler must never take the app down.
    """
    # Lazy import: reuse the scan-now single-flight + worker (one direction).
    from soc_ai.api.webui_api import (  # noqa: PLC0415
        _get_discovery_status,
        _run_discovery_task,
    )

    # Fixed wake cadence (minutes). Decoupled from the hours-granularity
    # interval so a freshly-toggled-on schedule starts within a wake, and the
    # interval check itself is what enforces the spacing. 5 min is cheap (the
    # body is a cheap settings read + timestamp compare unless a scan is due).
    wake_seconds = 300
    while True:
        await asyncio.sleep(wake_seconds)
        try:
            # Re-read every wake → GUI toggle / interval edits apply live.
            if not settings.discovery_schedule_enabled or not settings.discovery_enabled:
                continue
            status = _get_discovery_status(app.state)
            if status.running:
                continue  # a scan (manual or scheduled) is already in flight
            if not _discovery_due(status.last_scan, settings.discovery_schedule_interval_hours):
                continue
            status.running = True  # claim the single-flight slot before scheduling
            status._task = asyncio.create_task(_run_discovery_task(app.state))
        except asyncio.CancelledError:
            raise
        except Exception:
            _LOGGER.exception("discovery scheduler iteration failed; continuing")


async def _dossier_scheduler_loop(app: FastAPI, settings: Any) -> None:
    """Periodically refresh the host dossier (the network's asset context).

    Models :func:`_discovery_scheduler_loop` in every respect — fixed wake
    cadence, live settings read each wake (a config-console toggle applies
    without a restart), the shared "Rebuild now" single-flight slot so a manual
    and a scheduled sweep can never overlap, and a logged-and-swallowed failed
    iteration because a scheduler must never take the app down.

    The one deliberate difference is the due-check's input. Discovery compares
    against an ``app.state`` timestamp; this loop reads the newest
    ``dossier_run`` row, because an in-memory stamp is ``None`` after every
    restart and ``None`` reads as due — a restart loop would then re-sweep the
    entire network on each boot. The durable stamp is read once and cached onto
    the status object, so every later wake stays a settings read and a timestamp
    compare.

    A failing durable read degrades toward sweeping rather than toward never
    sweeping again: the sweep itself opens a ``dossier_run`` row against the same
    database, so a genuinely broken store returns immediately, and the worker
    stamps ``last_run`` in its ``finally`` regardless — there is no retry storm
    behind the fail-soft.
    """
    # Lazy import: reuse the rebuild-now single-flight + worker (one direction).
    from soc_ai.api.webui import _get_dossier_status, _run_dossier_task  # noqa: PLC0415
    from soc_ai.enrichment.host_dossier import latest_run_started_at  # noqa: PLC0415

    wake_seconds = 300
    while True:
        await asyncio.sleep(wake_seconds)
        try:
            # Re-read every wake → GUI toggle / interval edits apply live.
            if not settings.dossier_enabled or not settings.dossier_schedule_enabled:
                continue
            status = _get_dossier_status(app.state)
            if status.running:
                continue  # a sweep (manual or scheduled) is already in flight
            if status.last_run is None:
                try:
                    stamp = await latest_run_started_at(app.state.db_sessionmaker)
                except Exception:
                    _LOGGER.warning(
                        "host dossier: durable last-run read failed; treating the sweep "
                        "as due (continuing)",
                        exc_info=True,
                    )
                    stamp = None
                if stamp is not None:
                    status.last_run = stamp.isoformat()
                # RE-READ the shared slot: the check above happened before the
                # await, and a "Rebuild now" landing inside that window would
                # otherwise get a second network sweep started on top of it —
                # hundreds of hosts times several ES round trips, twice, which
                # is the connection-pool pressure that has frozen this app
                # before. (Read through the accessor, not the narrowed local:
                # the await is exactly where the value can change.)
                if _get_dossier_status(app.state).running:
                    continue
            if not _dossier_due(status.last_run, settings.dossier_schedule_interval_hours):
                continue
            status.running = True  # claim the single-flight slot before scheduling
            status._task = asyncio.create_task(_run_dossier_task(app.state, trigger="schedule"))
        except asyncio.CancelledError:
            raise
        except Exception:
            _LOGGER.exception("host dossier scheduler iteration failed; continuing")


async def _auto_triage_scheduler_loop(app: FastAPI, settings: Any) -> None:
    """Continuously drain the untriaged backlog when scheduled auto-triage is on.

    Mirrors :func:`_discovery_scheduler_loop`: a fixed wake cadence (derived from
    ``auto_triage_schedule_interval_minutes``), live settings read each wake (so a
    config-console toggle applies without a restart), and a no-op unless
    ``auto_triage_schedule_enabled``. Single-flight via the shared
    ``AutoTriageStatus.active`` slot, so a scheduled sweep and a manual ⚡ press
    can never overlap. A failed iteration is logged and the loop continues — the
    scheduler must never take the app down.
    """
    from soc_ai.webui import autotriage as at  # noqa: PLC0415

    # Fixed short wake cadence + an internal "is due" check (mirrors the discovery
    # scheduler). Sleeping the whole interval up front meant toggling the schedule
    # ON only took effect up to interval-length later; a 60s wake makes a fresh
    # enable fire on the next wake. ``_last_sweep`` is None until the first sweep so
    # the first enabled wake always fires — a 0.0 sentinel collided with a small
    # ``time.monotonic()`` on a freshly-booted host (monotonic's epoch is arbitrary,
    # near-zero right after boot), which wrongly read as "just swept" and skipped the
    # first sweep for up to one interval.
    _last_sweep: float | None = None
    while True:
        await asyncio.sleep(60)
        try:
            if not settings.auto_triage_schedule_enabled:
                continue
            interval_min = int(getattr(settings, "auto_triage_schedule_interval_minutes", 5))
            now = time.monotonic()
            if _last_sweep is not None and now - _last_sweep < max(60, interval_min * 60):
                continue
            if at.get_status(app.state).active:
                continue  # a sweep (manual or scheduled) is already in flight
            n = await at.start_config_sweep(app.state, started_by="auto-triage:scheduler")
            # Record the sweep time whether or not it launched targets. The ES
            # planning pass (one grouped aggregation per severity + per-group
            # fetches) is exactly what the interval throttles; on a drained
            # backlog every sweep plans 0 targets, so gating the timestamp on
            # ``n`` left ``_last_sweep`` unset and re-ran full planning every 60s,
            # ignoring ``auto_triage_schedule_interval_minutes``.
            _last_sweep = time.monotonic()
            if n:
                _LOGGER.info("auto-triage scheduler: launched a sweep of %d target(s)", n)
        except asyncio.CancelledError:
            raise
        except Exception:
            _LOGGER.exception("auto-triage scheduler iteration failed; continuing")


async def _hunt_schedule_loop(app: FastAPI) -> None:
    """Fire recurring (scheduled) hunts when they come due (E3.1).

    Mirrors :func:`_auto_triage_scheduler_loop`: a fixed 60s wake, live settings
    read each wake (a config-console toggle applies without a restart), a no-op
    unless ``hunt_schedules_enabled``. Each wake fetches the DUE schedules
    (:func:`soc_ai.store.hunt_schedules.due_schedules`) and spawns a normal hunt
    per schedule via the shared ``HuntConsoleManager`` (tagged ``kind="scheduled"``),
    then stamps ``last_run_at`` — but only after the spawn actually succeeds. A
    spawn rejected at the shared concurrency ceiling stays unstamped so the
    schedule remains due and retries on the next wake (no lost cycle).

    **Single-flight** is per-SCHEDULE, not global: distinct schedules run
    concurrently (the manager keys tasks by hunt_id, so they never collide), but a
    schedule can't re-fire while its own hunt is still running because
    :func:`mark_ran` resets its interval clock the instant a spawn succeeds — so the same
    schedule is no longer "due" next wake until the interval elapses again. This
    relies on the interval being ≥ the hunt runtime (enforced as a 60-min floor at
    the store). A per-schedule failure is logged and skipped so one bad schedule
    can never take out the others or the loop.

    Note (workers>1): a second uvicorn worker would run its own copy of this loop
    and double-fire every schedule — soc-ai runs a SINGLE worker today; distributed
    scheduler coordination is Epoch 6.2, deliberately not built here.
    """
    from soc_ai.store import hunt_schedules as hs_svc  # noqa: PLC0415
    from soc_ai.webui import hunt_console_manager as hcm  # noqa: PLC0415

    while True:
        await asyncio.sleep(60)
        try:
            settings = app.state.settings
            if not getattr(settings, "hunt_schedules_enabled", False):
                continue
            now = datetime.now(UTC).replace(tzinfo=None)  # naive UTC, matches the store
            async with app.state.db_sessionmaker() as db:
                due = await hs_svc.due_schedules(db, now)
            if not due:
                continue
            manager = hcm.get_manager(app.state)
            launched = 0
            for sched in due:
                try:
                    hunt_id = await manager.start(
                        app.state,
                        objective=sched.objective,
                        started_by="scheduler",
                        kind="scheduled",
                        starter="schedule",
                    )
                    if hunt_id is None:
                        # Rejected: the shared concurrency ceiling is full (or the
                        # generator died before hunt_created). Leave last_run_at
                        # UNSTAMPED so the schedule stays "due" and the next wake
                        # retries it — stamping here would silently drop a whole
                        # interval and show a "last ran" for a run that never began.
                        _LOGGER.warning(
                            "hunt scheduler: schedule id=%s could not start "
                            "(at capacity?) — left due to retry next wake",
                            sched.id,
                        )
                        continue
                    # Stamp the interval clock only AFTER a real spawn: this is the
                    # per-schedule single-flight guard and records the run that
                    # actually started. The loop is sequential, so the next wake
                    # can't fire mid-pass — a slow start() can't double-fire it.
                    async with app.state.db_sessionmaker() as db:
                        await hs_svc.mark_ran(db, sched.id, now)
                    launched += 1
                except asyncio.CancelledError:
                    raise
                except Exception:
                    _LOGGER.exception(
                        "hunt scheduler: schedule id=%s failed to fire; skipping", sched.id
                    )
                    # A schedule whose spawn RAISED (a broken objective, a bug in
                    # start()) is stamped so it can't retry-storm every wake — a
                    # permanently-bad schedule fires at most once per interval, not
                    # once per wake. This is distinct from the capacity rejection
                    # above (hunt_id is None), which is transient and SHOULD retry.
                    try:
                        async with app.state.db_sessionmaker() as db:
                            await hs_svc.mark_ran(db, sched.id, now)
                    except Exception:
                        _LOGGER.exception(
                            "hunt scheduler: schedule id=%s could not be stamped after "
                            "a failed spawn",
                            sched.id,
                        )
            if launched:
                _LOGGER.info("hunt scheduler: launched %d scheduled hunt(s)", launched)
        except asyncio.CancelledError:
            raise
        except Exception:
            _LOGGER.exception("hunt scheduler iteration failed; continuing")


# How many leads one wake reads before it decides. Wider than any sensible
# concurrency cap, because a lead that cites no documents is skipped and must
# not hold the slot of a lead behind it that does.
_LEAD_AUTO_HUNT_BATCH = 50

# How often the skip of one lead is said. The loop wakes every 60 seconds, so
# an unthrottled line would write sixty an hour about one lead that is not
# moving.
_LEAD_AUTO_HUNT_QUIET = timedelta(hours=1)


async def _leads_the_loop_may_hunt(db: Any) -> tuple[list[int], list[int]]:
    """The waiting leads, split by whether their observations cite a document.

    The second list is skipped rather than hunted: a hunt of a lead that cites
    nothing has no evidence to read first, so it searches the grid from
    scratch. The split is re-read on every wake, because the sweep can record
    documents for a lead that had none.
    """
    from soc_ai.hunting import lead_hunt  # noqa: PLC0415
    from soc_ai.store import leads as leads_store  # noqa: PLC0415

    cited: list[int] = []
    bare: list[int] = []
    for lead in await lead_hunt.leads_awaiting_a_hunt(db, limit=_LEAD_AUTO_HUNT_BATCH):
        rows = await leads_store.timeline(db, int(lead.id))
        (cited if leads_store.cites_documents(rows) else bare).append(int(lead.id))
    return cited, bare


def _say_the_skipped_leads(
    said: dict[int, datetime], no_documents: list[int], now: datetime
) -> dict[int, datetime]:
    """Log each skipped lead once an hour. Returns the times to keep.

    The returned map holds only the leads still being skipped, so a process
    that runs for months does not accumulate an entry per lead ever formed.
    """
    kept = {lead_id: at for lead_id, at in said.items() if lead_id in no_documents}
    for lead_id in no_documents:
        last = kept.get(lead_id)
        if last is None or (now - last) >= _LEAD_AUTO_HUNT_QUIET:
            kept[lead_id] = now
            _LOGGER.info(
                "lead auto-hunt: lead %s cites no documents, so it is not hunted. "
                "Run the sweep again to record them.",
                lead_id,
            )
    return kept


async def _lead_auto_hunt_loop(app: FastAPI) -> None:
    """Start a hunt for every lead that has never had one (D1).

    Mirrors :func:`_hunt_schedule_loop`'s discipline: a fixed 60s wake, live
    settings read each wake so a config-console toggle applies without a
    restart, and a no-op unless ``lead_auto_hunt``. It differs in what it
    reads: not a schedule table but the leads themselves.

    The loop starts the hunt rather than the sweep that forms the lead,
    because leads also form in the timer process that runs the priors, and
    that process cannot run an agent.

    The rule, in one sentence: an open lead with no hunt, never dismissed,
    with no hunt row that names it, oldest first, until the number of the
    loop's own lead hunts in flight reaches ``lead_auto_hunt_concurrency``.
    The selection lives in :func:`soc_ai.hunting.lead_hunt.leads_awaiting_a_hunt`
    and the start in :func:`soc_ai.hunting.lead_hunt.start_lead_hunt`, which
    the Hunt button on the lead calls as well.

    Before it selects, each wake settles every hunting lead whose hunt has
    finished, through :func:`soc_ai.store.leads.settle_finished_hunts`. The
    startup reaper runs the same call, so an install that upgrades with leads
    stuck in ``hunting`` needs no migration of data by hand.

    A lead whose observations cite no documents is skipped, not started: its
    hunt would have no evidence to read first and would search the grid from
    scratch. The skip is re-read on every wake, because the sweep can record
    documents later, but the log line about it is said once an hour per lead.

    One lead that fails is logged and the tick continues, so a single bad lead
    can never take out the others or the loop.

    Note (workers>1): a second uvicorn worker would run its own copy and could
    start a second hunt for the same lead between the console call and the
    mark. soc-ai runs a single worker today; distributed scheduler
    coordination is Epoch 6.2, as for the loops above.
    """
    from soc_ai.hunting import lead_hunt  # noqa: PLC0415

    # Per-process, per-lead: when the skip was last said. Rebuilt each wake
    # from the leads still being skipped, so it cannot grow without bound.
    said_no_documents: dict[int, datetime] = {}

    while True:
        await asyncio.sleep(60)
        try:
            settings = app.state.settings
            if not getattr(settings, "lead_auto_hunt", False):
                continue
            cap = max(1, int(getattr(settings, "lead_auto_hunt_concurrency", 2) or 1))

            async with app.state.db_sessionmaker() as db:
                # Bookkeeping before selection. A lead whose hunt finished
                # while this process was down, or before the settle rule
                # existed, moves now, and an errored one is back to open in
                # time for the selection below to retry it.
                settled = await leads_store.settle_finished_hunts(db)
                if settled:
                    _LOGGER.info(
                        "lead auto-hunt: settled %d lead(s) whose hunt had finished", settled
                    )
                running = await lead_hunt.running_auto_hunts(db)
                if running >= cap:
                    continue
                eligible, no_documents = await _leads_the_loop_may_hunt(db)

            said_no_documents = _say_the_skipped_leads(
                said_no_documents, no_documents, datetime.now(UTC).replace(tzinfo=None)
            )

            started = 0
            for lead_id in eligible:
                if running + started >= cap:
                    break
                try:
                    out = await lead_hunt.start_lead_hunt(
                        app.state, lead_id=lead_id, started_by=lead_hunt.AUTO_HUNT_ACTOR
                    )
                except asyncio.CancelledError:
                    raise
                except lead_hunt.LeadHuntRefused as exc:
                    # The lead closed or the console is full. Both are normal.
                    # The lead stays open and the next wake reads it again.
                    _LOGGER.info(
                        "lead auto-hunt: lead %s did not take a hunt (%s)", lead_id, exc.reason
                    )
                    continue
                except Exception:
                    _LOGGER.exception(
                        "lead auto-hunt: lead %s failed to start a hunt; skipping", lead_id
                    )
                    continue
                if out.existing:
                    continue
                started += 1
                _LOGGER.info("lead auto-hunt: lead %s started hunt %s", lead_id, out.hunt_id)
        except asyncio.CancelledError:
            raise
        except Exception:
            _LOGGER.exception("lead auto-hunt iteration failed; continuing")


def _persist_bootstrap_credential(settings: Any, created_pw: str) -> None:
    """Write the one-shot bootstrap admin password to a locked-down sidecar
    file instead of the shared log stream, and log only a pointer to it.

    setup.sh pre-generates BOOTSTRAP_ADMIN_PASSWORD so this path is off the
    happy path. journald/container logs are often readable by the same
    audience (other analysts, integrations) this credential must stay secret
    from. Mirrors the chmod(0o600) treatment backup.py gives the Ed25519
    signing key sidecar.
    """
    cred_path = bootstrap_credential_path(settings)
    try:
        cred_path.write_text(created_pw + "\n")
        cred_path.chmod(0o600)
    except OSError:
        # Data dir not writable for some reason — fall back to the log line
        # rather than leaving the operator with no way to reach the account.
        _LOGGER.warning(
            "BOOTSTRAP CREDENTIAL (change at first login, then scrub this log line): "
            "initial admin user 'admin' password=%s",
            created_pw,
        )
    else:
        _LOGGER.warning(
            "BOOTSTRAP CREDENTIAL written to %s (mode 0600) — log in as 'admin', "
            "change the password, then delete that file.",
            cred_path,
        )


def _require_prompt_assets() -> None:
    """Refuse to serve when a declared prompt asset is not on disk.

    The prompt assets (``soc_ai.agent.prompts.PROMPT_ASSETS``) are markdown
    files that live beside the package rather than inside it, so a build that
    forgets to copy them produces an app that starts, answers, and is wrong:
    the primer degrades to a stub that tells the model the query language is
    unavailable, and the verdicts that come back still look like verdicts.

    This is the one place the product prefers a crash. The standing rule is
    that a false all-clear outranks a crash, and it holds for upstreams: a
    half-answering grid is reported, not fatal, because the honest degraded
    answer exists and we can hand it to the analyst. Here there is no honest
    degraded answer to hand over. The absence is invisible in the output, it
    is knowable with two stat calls before the first request, and it is a
    packaging fault an operator fixes by redeploying, so we fail at the point
    where somebody is already watching, rather than at the point where an
    analyst is trusting the answer. The doctor carries the same finding
    (``check_prompt_assets``) for the installs that reach it another way.
    """
    from soc_ai.agent.prompts import missing_prompt_assets  # noqa: PLC0415 - startup-only

    missing = missing_prompt_assets()
    if not missing:
        return
    detail = "; ".join(f"{asset.name} ({asset.path}): {asset.cost}" for asset in missing)
    raise RuntimeError(
        f"refusing to start, {len(missing)} prompt asset(s) missing. {detail}. "
        "The deployment is incomplete; redeploy from an image or install that ships "
        "the docs/ directory, then run `soc-ai doctor` to confirm."
    )


async def _reap_orphans_at_startup(db_sessionmaker: Any) -> None:
    """Resolve every row the previous process left mid-flight.

    Anything still ``running``/``pending`` when we boot can never finish — the
    background task that owned it died with the old process — so each store is
    swept here, with the terminal status that fits its semantics: ``interrupted``
    where the work is re-runnable, ``error`` where it is a one-shot measurement
    or an answer nobody will ever receive.

    Split out of :func:`_init_store` because it is ONE concern spread over five
    stores, and the list only grows: each new background-backed table needs a
    line here, and a missing one is invisible until a restart happens to land
    mid-run.
    """
    # Investigations: mark 'interrupted' (NOT 'error') — a clean restart cut them
    # off; they didn't fail. 'interrupted' is re-huntable, so continuous
    # auto-triage (or a manual re-hunt) picks them back up, and the UI shows a
    # benign state instead of a scary "error" in a healthy environment.
    async with db_sessionmaker() as db:
        orphaned = await inv_svc.reap_stale_running(
            db, older_than_minutes=None, status="interrupted"
        )
    if orphaned:
        _LOGGER.info("reaped %d orphaned 'running' investigation(s) at startup", orphaned)

    # Hunts mirror the investigation reaper: re-runnable, so 'interrupted'.
    async with db_sessionmaker() as db:
        orphaned_hunts = await hunt_svc.reap_stale_running(
            db, older_than_minutes=None, status="interrupted"
        )
    if orphaned_hunts:
        _LOGGER.info("reaped %d orphaned 'running' hunt(s) at startup", orphaned_hunts)

    # Leads: a lead whose hunt finished with no process there to settle it,
    # and every lead an older release left in 'hunting'. Runs after the hunt
    # reaper, so an orphaned hunt is terminal by the time the rule reads it.
    async with db_sessionmaker() as db:
        settled = await leads_store.settle_finished_hunts(db)
    if settled:
        _LOGGER.info("settled %d lead(s) whose hunt had finished, at startup", settled)

    # Backtests: mark 'error' — a backtest is a one-shot measurement whose replay
    # task died, not a re-huntable target.
    async with db_sessionmaker() as db:
        orphaned_bt = await bt_svc.reap_stale_running(db, older_than_minutes=None, status="error")
    if orphaned_bt:
        _LOGGER.info("reaped %d orphaned 'running' backtest(s) at startup", orphaned_bt)

    # Investigation chat: a 'pending' assistant row would otherwise stay pending —
    # empty — forever, because the task that was writing the answer is gone.
    async with db_sessionmaker() as db:
        orphaned_chat = await chat_svc.reap_stale_pending(db, older_than=None)
    if orphaned_chat:
        _LOGGER.info("reaped %d orphaned 'pending' chat turn(s) at startup", orphaned_chat)

    # …and the dashboard's general chat, a SEPARATE table with its own reaper
    # (chat_svc only scans chat_messages). Skipping it leaves an empty answer
    # bubble on the landing screen — the first thing every analyst sees — with no
    # path back to 'done'.
    async with db_sessionmaker() as db:
        orphaned_general = await general_chat_svc.reap_stale_pending(db, older_than=None)
    if orphaned_general:
        _LOGGER.info(
            "reaped %d orphaned 'pending' dashboard chat turn(s) at startup", orphaned_general
        )

    # Expired sessions: get_session_user rejects them but leaves the row, so an
    # abandoned cookie's row lingers forever. Sweep them here (storage hygiene) —
    # the lookup is indexed so this is not a hot-path cost, just unbounded growth.
    async with db_sessionmaker() as db:
        purged_sessions = await purge_expired_sessions(db)
    if purged_sessions:
        _LOGGER.info("purged %d expired session(s) at startup", purged_sessions)


async def _init_store(db_engine: Any, settings: Any, secret_box: Any = None) -> Any:
    """Migrate the store, bootstrap the admin, apply config overrides, reap orphans.

    Returns the sessionmaker. Migration failure disposes the engine and re-raises
    (the app must not serve against a corrupt/newer schema).
    """
    try:
        await run_migrations(db_engine)
    except Exception:
        _LOGGER.exception(
            "store migration failed — DB at %s is corrupt or newer than this build; "
            "back up/remove the file or upgrade soc-ai",
            settings.soc_ai_data_dir / "soc-ai.db",
        )
        await db_engine.dispose()
        raise
    db_sessionmaker = make_sessionmaker(db_engine)
    async with db_sessionmaker() as db:
        created_pw = await bootstrap_admin(db, settings.bootstrap_admin_password)
    if created_pw is not None:
        _persist_bootstrap_credential(settings, created_pw)

    # Re-apply persisted admin config overrides onto the live settings singleton
    # so operator choices (e.g. Oracle on/off) survive a restart.
    async with db_sessionmaker() as db:
        overrides = await load_overrides(db)
    apply_to_settings(settings, overrides, secret_box=secret_box)
    if overrides:
        _LOGGER.info("applied %d persisted config override(s)", len(overrides))

    # Seed the builtin hunt templates (E3.2) — idempotent upsert-by-name, so it's
    # safe on every startup (never duplicates a builtin, never touches a custom
    # template). Fail-soft: a seed failure must not block serving; the picker just
    # falls back to whatever templates already exist (or the frontend's static
    # pills if the store is empty).
    try:
        async with db_sessionmaker() as db:
            seeded = await hunt_templates_svc.seed_builtins(db)
        if seeded:
            _LOGGER.info("seeded/refreshed %d builtin hunt template(s)", seeded)
    except Exception:
        _LOGGER.warning("builtin hunt-template seed failed; continuing", exc_info=True)

    # Demo mode: seed the sanitized recorded-run fixtures so the UI has
    # investigations/hunts/backtests to browse. Idempotent per row (restart-safe)
    # and fail-soft — a missing or invalid fixtures.json must never block
    # serving; the demo just starts with whatever the store already holds.
    if settings.soc_ai_demo:
        try:
            from soc_ai.demo.fixtures import (  # noqa: PLC0415
                DEFAULT_FIXTURES,
                load_fixtures,
                seed_fixtures,
            )

            added = await seed_fixtures(db_sessionmaker, load_fixtures(DEFAULT_FIXTURES))
            if added:
                _LOGGER.info("demo mode: seeded %d fixture row(s)", added)
        except Exception:
            _LOGGER.warning("demo fixture seed failed; continuing with empty store", exc_info=True)
        # The hunt catalog's sweep trail is generated from the shipped catalog,
        # not read from the fixture file (see soc_ai/demo/catalog_trail.py), so
        # it has its own fail-soft step: a fixture problem must not cost the
        # Operate hub its one live panel, and the reverse holds too.
        try:
            from soc_ai.demo.catalog_trail import seed_catalog_trail  # noqa: PLC0415

            if await seed_catalog_trail(db_sessionmaker):
                _LOGGER.info("demo mode: seeded a week of hunt catalog sweeps")
        except Exception:
            _LOGGER.warning("demo catalog trail seed failed; continuing without it", exc_info=True)

    await _reap_orphans_at_startup(db_sessionmaker)

    return db_sessionmaker


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:  # noqa: PLR0915 — linear app setup
    """Wire up app-scoped clients, tear them down on shutdown."""
    settings = get_settings()
    logging.basicConfig(
        level=settings.log_level,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    # Before anything is built: the prompt assets are a packaging fact, and a
    # deployment missing one answers wrongly rather than not at all.
    _require_prompt_assets()
    # DB + persisted overrides FIRST, before any client is built. Connection /
    # secret Danger-Zone overrides feed the SO/ES/LiteLLM clients, so they must
    # land on `settings` before make_auth/ElasticClient/etc. read it. The secret
    # box decrypts at-rest secret overrides (None when CONFIG_SECRET_KEY is unset
    # → secret overrides are skipped, env values stand).
    secret_box = make_secret_box(settings)
    db_engine = make_engine(settings)
    db_sessionmaker = await _init_store(db_engine, settings, secret_box)

    _LOGGER.info(
        "soc-ai starting; auth=%s, host=%s",
        "connect" if settings.use_connect_api else "kratos",
        settings.so_host,
    )

    # Loud warning when API auth is disabled — with auth off, require_admin_api is
    # a no-op, so secret mutation, user creation, and token minting are open to any
    # caller that can reach the port. Acceptable for loopback-only dev; a real risk
    # if the bind is non-loopback (the docker default is 0.0.0.0).
    if not settings.api_auth_required:
        _loopback = {"127.0.0.1", "::1", "localhost", ""}
        if str(settings.soc_ai_host) not in _loopback:
            _LOGGER.warning(
                "API_AUTH_REQUIRED=false AND bind host is non-loopback (%s) — admin "
                "endpoints (secret edit, user/token creation) are UNAUTHENTICATED and "
                "reachable on the network. Set API_AUTH_REQUIRED=true for any shared deploy.",
                settings.soc_ai_host,
            )
        else:
            _LOGGER.warning(
                "API_AUTH_REQUIRED=false — running unauthenticated (loopback bind %s). "
                "Dev/lab only; set API_AUTH_REQUIRED=true before exposing the port.",
                settings.soc_ai_host,
            )

    auth = make_auth(settings)
    elastic = ElasticClient(settings)
    misp = MispClient(settings) if settings.misp_url is not None else None
    audit = AuditLogger(settings, elastic)
    enrichment = build_local_enrichment_context(settings)
    # Ed25519 signer for decision-record exports (load-or-generate the key).
    # Best-effort: a signing failure must not block startup — exports then carry
    # the sha256 checksum only.
    from soc_ai.store.signing import DecisionSigner  # noqa: PLC0415

    try:
        decision_signer: Any = DecisionSigner.load_or_create(settings.soc_ai_data_dir)
    except Exception:
        _LOGGER.warning("decision-record signer unavailable; exports use checksum only")
        decision_signer = None

    app.state.settings = settings
    app.state.secret_box = secret_box
    app.state.auth = auth
    app.state.elastic = elastic
    app.state.misp = misp
    app.state.audit = audit
    app.state.enrichment = enrichment
    app.state.decision_signer = decision_signer
    app.state.db_engine = db_engine
    app.state.db_sessionmaker = db_sessionmaker

    # Demo mode: cache the parsed fixture document ONCE for the replay runner —
    # the two allowlisted POSTs (soc_ai/demo/replay.py) look up replays[] per
    # request without re-reading the file. Fail-soft like the seed hook in
    # _init_store: a missing/invalid fixtures.json leaves the cache None, and
    # replays then report unknown alerts the same way the live pipeline does.
    app.state.demo_fixtures = None
    if settings.soc_ai_demo:
        try:
            from soc_ai.demo.fixtures import DEFAULT_FIXTURES, load_fixtures  # noqa: PLC0415

            app.state.demo_fixtures = load_fixtures(DEFAULT_FIXTURES)
        except Exception:
            _LOGGER.warning(
                "demo replay fixtures unavailable; replay lookups will find nothing",
                exc_info=True,
            )

    reaper_task = asyncio.create_task(_reaper_loop(db_sessionmaker, settings))
    discovery_task = asyncio.create_task(_discovery_scheduler_loop(app, settings))
    dossier_task = asyncio.create_task(_dossier_scheduler_loop(app, settings))
    autotriage_task = asyncio.create_task(_auto_triage_scheduler_loop(app, settings))
    hunt_schedule_task = asyncio.create_task(_hunt_schedule_loop(app))
    lead_auto_hunt_task = asyncio.create_task(_lead_auto_hunt_loop(app))
    eval_nightly_task = asyncio.create_task(_eval_nightly_loop(app, settings))
    spec_sweep_task = asyncio.create_task(_hunt_spec_sweep_loop(app))
    prior_sweep_task = asyncio.create_task(_prior_sweep_loop(app))
    audit_verify_task = asyncio.create_task(_audit_verify_loop(app, settings))
    health_probe_task = asyncio.create_task(_health_probe_loop(app, settings))

    try:
        yield
    finally:
        _LOGGER.info("soc-ai shutting down; releasing clients")
        reaper_task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await reaper_task
        discovery_task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await discovery_task
        dossier_task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await dossier_task
        autotriage_task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await autotriage_task
        hunt_schedule_task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await hunt_schedule_task
        lead_auto_hunt_task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await lead_auto_hunt_task
        eval_nightly_task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await eval_nightly_task
        spec_sweep_task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await spec_sweep_task
        prior_sweep_task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await prior_sweep_task
        health_probe_task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await health_probe_task
        audit_verify_task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await audit_verify_task
        # An in-flight quality-eval worker (scheduled or run-now) holds its own
        # engine/ES clients — cancel + drain like the discovery worker below.
        from soc_ai.api.webui_api import _get_quality_eval_status  # noqa: PLC0415

        _qs = _get_quality_eval_status(app.state)
        if _qs._task is not None and not _qs._task.done():
            _qs._task.cancel()
            with contextlib.suppress(BaseException):
                await _qs._task
        # A scheduled (or manual "Scan now") discovery worker may be mid-scan,
        # tracked on the shared single-flight status object (the same one the
        # scan-now endpoint uses). Cancel + drain it BEFORE the ES/DB clients it
        # holds are torn down, so a shutdown racing an in-flight scan doesn't log
        # a spurious "scan failed".
        from soc_ai.api.webui_api import _get_discovery_status  # noqa: PLC0415

        _st = _get_discovery_status(app.state)
        if _st._task is not None and not _st._task.done():
            _st._task.cancel()
            with contextlib.suppress(BaseException):
                await _st._task
        # Same for an in-flight host-dossier sweep (scheduled or "Rebuild now"):
        # it holds the ES + DB clients for minutes at a time, so it must be
        # cancelled and drained BEFORE they are torn down or it lands a
        # use-after-close ES search partway through the network.
        from soc_ai.api.webui import _get_dossier_status  # noqa: PLC0415

        _ds = _get_dossier_status(app.state)
        if _ds._task is not None and not _ds._task.done():
            _ds._task.cancel()
            with contextlib.suppress(BaseException):
                await _ds._task
        # The scheduler LOOPS are cancelled above, but the WORKER tasks they
        # spawn (auto-triage drain, backtest replay) and manually-started hunt
        # console drains hold references to the ES + DB clients. Cancel + drain
        # them here too, before those clients are torn down, so an in-flight
        # worker can't do a use-after-close ES search / DB write on shutdown.
        from soc_ai.webui import autotriage as _at  # noqa: PLC0415
        from soc_ai.webui import backtest as _bac  # noqa: PLC0415
        from soc_ai.webui import chat_manager as _cm  # noqa: PLC0415
        from soc_ai.webui import hunt_console_manager as _hcm  # noqa: PLC0415
        from soc_ai.webui import hunt_manager as _hm  # noqa: PLC0415

        _worker_tasks: list[asyncio.Task[Any]] = []
        _at_task = _at.get_status(app.state)._task
        if _at_task is not None:
            _worker_tasks.append(_at_task)
        _bac_task = _bac.get_status(app.state)._task
        if _bac_task is not None:
            _worker_tasks.append(_bac_task)
        _worker_tasks.extend(_hcm.get_manager(app.state)._tasks.values())
        # HuntManager (per-alert manual Investigate via POST /hunt) and ChatManager
        # (chat turns) hold the same ES/DB references via app.state — drain them too,
        # else an in-flight Investigate or chat turn can use-after-close on shutdown.
        _worker_tasks.extend(_hm.get_manager(app.state)._tasks.values())
        _worker_tasks.extend(_cm.get_manager(app.state)._tasks.values())
        # The "Chat about this hunt" follow-up turns (HuntChatManager, stored as
        # hunt_events) are a THIRD chat drainer. Without this, a pending hunt-chat
        # turn is abandoned mid-flight at shutdown — never cancelled, so its
        # done-callback backstop never fires and the row stays 'pending' forever
        # (the hunt's chat then spins and every later POST .../chat 409s).
        _worker_tasks.extend(_hcm.get_chat_manager(app.state)._tasks.values())
        # Demo replay drains (soc_ai/demo/replay.py start_background_replay) hold
        # the DB sessionmaker via the recorder — drain them too, else an in-flight
        # replay can write after db_engine.dispose(). Empty set outside demo.
        _worker_tasks.extend(getattr(app.state, "demo_replay_tasks", set()))
        for _t in _worker_tasks:
            if not _t.done():
                _t.cancel()
        for _t in _worker_tasks:
            with contextlib.suppress(BaseException):
                await _t
        await auth.aclose()
        await elastic.aclose()
        if misp is not None:
            await misp.aclose()
        await db_engine.dispose()


def _resolve_cors_origins(cors_setting: str, so_host: str) -> list[str]:
    """Resolve the CORS allow-origins list from config (pure, testable).

    Precedence: an explicit ``"*"`` (opt-in wildcard) > a comma-separated
    ``CORS_ALLOW_ORIGINS`` list > the SO host. With none of those configured we
    **fail closed** to ``[]`` (no cross-origin callers) rather than ``["*"]`` —
    the React app is same-origin, and a wildcard would let any site read
    responses on behalf of a bearer-token caller.
    """
    cors = cors_setting.strip()
    if cors == "*":
        return ["*"]
    if cors:
        return [o.strip() for o in cors.split(",") if o.strip()]
    if so_host:
        return [so_host]
    return []


# Demo mode (SOC_AI_DEMO): the only mutating routes left open — the replay
# triggers (Task 6 wires them to recorded fixtures). Mounted paths verified
# against the live route table: the soc_ai.api.routes router is included with
# NO prefix, so investigate lives at /investigate (not /api/v1/investigate);
# the webui hunts router is under /api/v1.
#
# The Dashboard general chat is here too, and it is the one entry that is not a
# replay: on a demo BOTH its verbs resolve inside soc_ai/api/webui/routes_chat.py
# without touching the store (see the demo section there), so allow-listing them
# hands a visitor no write. Both verbs are needed and neither is surplus:
# POST is the reply itself — this box sits on the LANDING SCREEN, so refusing it
# means the first thing a visitor touches errors; DELETE backs the panel's
# "Clear conversation" control, which appears as soon as a reply does, and
# refusing it would put an error under the landing screen instead. PUT/PATCH are
# not routes here and stay refused.
_DEMO_WRITE_ALLOW: set[tuple[str, str]] = {
    ("POST", "/investigate"),
    ("POST", "/api/v1/hunt"),
    ("POST", "/api/v1/chat"),
    ("DELETE", "/api/v1/chat"),
}

# Chat routes carry a variable id in the path, so they can't live in the
# exact-match set above — match them by (method, pattern). In demo mode these
# POSTs are turned into canned, ZERO-EGRESS replies by the demo branches in the
# chat/hunt route handlers and managers (soc_ai/api/webui/routes_chat.py,
# soc_ai/webui/chat_manager.py, host_chat_manager.py, hunt_console_manager.py);
# ``/api/v1/hunts/chat`` (hunt-start) is wired to a fixture replay in a later
# task. The host chat's DELETE is the one non-POST: like the general chat's
# DELETE it backs the panel's "Clear conversation" control and, on a demo,
# deletes nothing (routes_chat serves it as a no-op) — refusing it would put an
# error under the first reply a visitor gets.
# Anchored ``^...$`` so a pattern can only allow the exact chat routes — never a
# broader mutating route that merely contains the substring.
_DEMO_WRITE_ALLOW_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("POST", re.compile(r"^/api/v1/investigations/[^/]+/chat$")),
    ("POST", re.compile(r"^/api/v1/hunts/[^/]+/chat$")),
    ("POST", re.compile(r"^/api/v1/hunts/chat$")),  # hunt-start → seeded hunt id (ephemeral)
    ("POST", re.compile(r"^/api/v1/dossiers/[^/]+/chat$")),
    ("DELETE", re.compile(r"^/api/v1/dossiers/[^/]+/chat$")),
)


# A field whose name matches this is reported WITHOUT its value. See
# `_validation_error_without_input` for why: the rejected value of a credential
# field is the plaintext secret, and a 4xx body is copied into proxy logs.
_SECRET_FIELD_RE = re.compile(r"pass|secret|token|key|credential|otp|pin", re.IGNORECASE)

# The request parts pydantic names in `loc`. They are not field names, so they
# are dropped before the field is composed.
_LOC_PARTS = frozenset({"body", "query", "path", "header", "cookie"})

# How much of a rejected value the hint quotes. Long enough to recognise a
# typo, short enough that a pasted document does not become the error message.
_HINT_VALUE_CHARS = 60


def _validation_hint(err: dict[str, Any]) -> str:
    """One sentence for one rejected field: what it is, what is wrong, what arrived."""
    parts = [str(p) for p in (err.get("loc") or ()) if str(p) not in _LOC_PARTS]
    field = ".".join(parts) or "the request"
    message = str(err.get("msg") or "is not valid").strip()
    if message:
        message = message[0].lower() + message[1:]
    if _SECRET_FIELD_RE.search(field):
        return f"{field} {message}."
    if "input" not in err:
        return f"{field} {message}."
    value = str(err.get("input"))
    if len(value) > _HINT_VALUE_CHARS:
        value = value[:_HINT_VALUE_CHARS] + "…"
    return f"{field} {message}; got '{value}'"


def create_app() -> FastAPI:  # noqa: PLR0915 - app factory wires many middlewares + routers
    """Application factory."""
    # Gate the interactive docs + raw schema behind a setting (off in prod) so a
    # security product doesn't publish its full admin API surface unauthenticated.
    try:
        _expose_docs = get_settings().expose_api_docs
    except Exception:
        _expose_docs = False
    app = FastAPI(
        title="soc-ai",
        description="Open, self-hosted LLM-powered triage assistant for Security Onion.",
        # Single source of truth: the installed package version (pyproject).
        # Was hardcoded "0.1.0", which drifted from the `__version__` the
        # /healthz and /metrics routes already report.
        version=__version__,
        lifespan=lifespan,
        docs_url="/docs" if _expose_docs else None,
        redoc_url="/redoc" if _expose_docs else None,
        openapi_url="/openapi.json" if _expose_docs else None,
    )

    @app.exception_handler(RequestValidationError)
    async def _validation_error_without_input(
        request: Request, exc: RequestValidationError
    ) -> JSONResponse:
        """422 with the same ``reason`` + ``hint`` shape every other 4xx uses.

        FastAPI's default handler answers with a list of error dicts. The SPA
        reads ``detail.reason`` and ``detail.hint`` everywhere else, so a
        validation failure was the one refusal it could not render, and the
        dogfood saw a bare "422" toast. The hint names the field, says what is
        wrong with it and quotes the value.

        The value is quoted with one exception, and it is the reason this
        handler exists. For every credential field in this API — ``/login``'s
        password, create-user's password, ``/me/password``'s current AND new
        password — the rejected value IS the plaintext secret, and a 422 is
        exactly what an over-long one produces. The echoed plaintext then lands
        wherever 4xx bodies land: reverse-proxy capture logs, frontend error
        reporters, browser devtools history. A field whose name looks like a
        credential is reported without its value.
        """
        hints = [_validation_hint(err) for err in exc.errors()]
        hint = hints[0] if hints else "The request is not valid."
        if len(hints) > 1:
            hint = f"{hint} {len(hints) - 1} more fields are not valid."
        return JSONResponse(
            status_code=422,
            content={"detail": jsonable_encoder({"reason": "bad_request", "hint": hint})},
        )

    try:
        _demo = get_settings().soc_ai_demo
    except Exception:
        _demo = False
    if _demo:
        # Demo read-only lock: refuse every mutating request with the structured
        # 403 shape the SPA already renders (detail.reason + detail.hint), except
        # the replay triggers in _DEMO_WRITE_ALLOW, which replay recorded runs
        # instead of doing real work (their handlers hit the egress guards if
        # they try). GET/HEAD/OPTIONS pass untouched — /healthz (docker
        # healthcheck) and all reads are unaffected. SOC_AI_DEMO is env-only
        # (not a UI-editable override), so gating registration at create time is
        # safe and keeps the non-demo request path completely untouched.
        # Registered FIRST → innermost middleware: on a public demo the refusal
        # is the most-served mutating response, so it must flow back out through
        # _security_headers (and CORSMiddleware), which are registered after it
        # and therefore wrap outside it.
        @app.middleware("http")
        async def _demo_readonly(request: Any, call_next: Any) -> Response:
            _path = request.url.path
            _allowed = (request.method, _path) in _DEMO_WRITE_ALLOW or any(
                request.method == m and p.match(_path) for m, p in _DEMO_WRITE_ALLOW_PATTERNS
            )
            if request.method in {"POST", "PUT", "PATCH", "DELETE"} and not _allowed:
                return JSONResponse(
                    status_code=403,
                    content={
                        "detail": {
                            "reason": "demo_mode",
                            "hint": "Demo — read-only replay; this action is disabled.",
                        }
                    },
                )
            response: Response = await call_next(request)
            return response

    # Cross-origin API clients (automation / integrations hosted on another
    # origin) fetch soc-ai cross-origin (the React /app is same-origin and needs
    # no CORS). Scope to CORS_ALLOW_ORIGINS if set, else the SO host; "*" only as
    # a last resort (with a warning). allow_credentials stays False — the
    # cross-origin caller authenticates with a bearer token, not a cookie.
    # get_settings() may raise at import-time construction if no .env is present
    # (e.g. CI just importing the module); fall back to a warned "*" then.
    try:
        _settings = get_settings()
        _cors = _settings.cors_allow_origins.strip()
        _so_host = str(_settings.so_host).rstrip("/") if _settings.so_host else ""
    except Exception:
        _cors, _so_host = "", ""
    cors_origins = _resolve_cors_origins(_cors, _so_host)
    if cors_origins == ["*"]:
        _LOGGER.warning("CORS allow_origins='*' — set CORS_ALLOW_ORIGINS (or SO_HOST) to scope it")
    elif not cors_origins:
        _LOGGER.warning(
            "CORS allow_origins empty — no cross-origin callers permitted; "
            "set CORS_ALLOW_ORIGINS (or SO_HOST) to enable cross-origin API clients"
        )
    app.add_middleware(
        CORSMiddleware,
        allow_origins=cors_origins,
        allow_credentials=False,
        allow_methods=["*"],
        allow_headers=["*"],
        expose_headers=["*"],
    )

    try:
        _csp = get_settings().content_security_policy.strip()
    except Exception:
        _csp = ""

    @app.middleware("http")
    async def _security_headers(request: Any, call_next: Any) -> Response:
        """Set conservative security response headers on every response.

        CSP (``content_security_policy``, default tuned for the bundled Vite SPA)
        plus ``frame-ancestors 'none'`` / ``X-Frame-Options: DENY`` block
        clickjacking; ``Cross-Origin-Opener-Policy`` isolates the browsing
        context. HSTS is only sent over HTTPS so a plain-HTTP dev run is
        unaffected.
        """
        response: Response = await call_next(request)
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        response.headers.setdefault(
            "Permissions-Policy", "geolocation=(), microphone=(), camera=()"
        )
        response.headers.setdefault("Cross-Origin-Opener-Policy", "same-origin")
        if _csp:
            response.headers.setdefault("Content-Security-Policy", _csp)
        # Emit HSTS when the browser reached us over HTTPS — directly, or via a
        # TLS-terminating reverse proxy that forwards plain HTTP with
        # X-Forwarded-Proto: https. Mirrors _request_is_https (webui_api) so a
        # proxy-fronted HTTPS deployment doesn't silently lose HSTS.
        _fwd_proto = request.headers.get("x-forwarded-proto", "").split(",")[0].strip().lower()
        if request.url.scheme == "https" or _fwd_proto == "https":
            response.headers.setdefault(
                "Strict-Transport-Security", "max-age=63072000; includeSubDomains"
            )
        return response

    # /api/v1/login is unauthenticated by design ("this IS the gate") and runs
    # before the login throttle's counters are touched, so it's the one route an
    # anonymous caller can flood with an arbitrarily large request body — the
    # deployed stack terminates TLS in uvicorn directly with nothing in front to
    # impose a size cap. Reject early on a declared Content-Length so the body is
    # never buffered; LoginIn's own Field(max_length=...) is defense in depth for
    # callers that omit Content-Length.
    _LOGIN_MAX_BODY_BYTES = 8 * 1024  # ample for a username+password JSON body

    @app.middleware("http")
    async def _login_body_size_guard(request: Any, call_next: Any) -> Response:
        if request.url.path == "/api/v1/login":
            content_length = request.headers.get("content-length")
            if (
                content_length is not None
                and content_length.isdigit()
                and int(content_length) > _LOGIN_MAX_BODY_BYTES
            ):
                return JSONResponse(
                    status_code=413,
                    content={
                        "detail": {
                            "reason": "payload_too_large",
                            "hint": "Login request body too large.",
                        }
                    },
                )
        response: Response = await call_next(request)
        return response

    try:
        _rl_limit = get_settings().api_rate_limit_per_min
    except Exception:
        _rl_limit = 0
    if _rl_limit > 0:
        # ip -> [window (monotonic minute), count]. Per-app-instance, bounded.
        app.state.rate_buckets = {}

        from soc_ai.api.webui_api import client_ip as _client_ip  # noqa: PLC0415

        @app.middleware("http")
        async def _rate_limit(request: Any, call_next: Any) -> Response:
            # The limiter counts API calls, not page loads. One load of the
            # SPA pulls a dozen JavaScript chunks and a document, and counting
            # those spent the minute's budget on the app's own assets. The
            # browser then rendered a blank screen with 429s in the console.
            # Health checks are exempt for the same reason they always were.
            path = request.url.path
            if path in {"/healthz", "/app"} or path.startswith("/app/"):
                exempt: Response = await call_next(request)
                return exempt
            # Proxy-aware: attribute to the real client, not a shared proxy IP,
            # when proxy_trusted_ips is configured (else the socket peer). Read the
            # resolved settings off app.state (set at startup) rather than a
            # per-request get_settings(); client_ip tolerates a missing state.
            ip = _client_ip(request, getattr(request.app.state, "settings", None))
            window = int(time.monotonic()) // 60
            buckets: dict[str, list[int]] = app.state.rate_buckets
            entry = buckets.get(ip)
            if entry is None or entry[0] != window:
                if len(buckets) > 8192:  # crude bound against unique-IP floods
                    buckets.clear()
                buckets[ip] = [window, 1]
            else:
                entry[1] += 1
                if entry[1] > _rl_limit:
                    return JSONResponse(
                        status_code=429,
                        headers={"Retry-After": "60"},
                        content={
                            "detail": {
                                "reason": "rate_limited",
                                "hint": (
                                    f"This address sent more than {_rl_limit} requests in one "
                                    "minute. Wait 60 s and try again."
                                ),
                            }
                        },
                    )
            response: Response = await call_next(request)
            return response

    app.include_router(router)
    # Open (pre-auth) endpoints first so FastAPI resolves /api/v1/login before
    # the auth-gated router's blanket dependency can reject the request.
    app.include_router(api_v1_open_router, prefix="/api/v1")
    app.include_router(api_v1_router, prefix="/api/v1")
    # The React SPA at /app. Only mounted when a build is present so source-only
    # checkouts still boot.
    app.state.spa_mounted = FRONTEND_DIST.is_dir()
    if app.state.spa_mounted:
        app.mount("/app", SpaStaticFiles(directory=FRONTEND_DIST, html=True), name="app")
    else:
        _LOGGER.info("frontend build not found at %s — /app not served", FRONTEND_DIST)

    # Bare `/` → the React app front door. The SPA is always built in deployment;
    # if `spa_mounted` is False, /app isn't served (startup logged a warning) and
    # this redirect 404s — which is the correct signal that the build is missing.
    @app.get("/", include_in_schema=False)
    async def _root() -> RedirectResponse:
        return RedirectResponse("/app/alerts", 307)

    return app


app = create_app()


# CLI entry now lives in soc_ai.cli; pyproject's [project.scripts] points
# `soc-ai` there. The systemd unit still uses `uvicorn soc_ai.main:app`
# directly, so this module just defines the FastAPI `app`.
