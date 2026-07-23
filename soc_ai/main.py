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

from fastapi import FastAPI
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
from soc_ai.config import get_settings
from soc_ai.so_client.auth import make_auth
from soc_ai.so_client.elastic import ElasticClient
from soc_ai.store import backtests as bt_svc
from soc_ai.store import chat as chat_svc
from soc_ai.store import hunt_templates as hunt_templates_svc
from soc_ai.store import hunts as hunt_svc
from soc_ai.store import investigations as inv_svc
from soc_ai.store.auth import bootstrap_admin
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

    The chat sweep rides the same cadence: it marks ``pending`` assistant chat
    rows older than ``chat_turn_timeout_s`` as ``error`` (a turn still inside its
    timeout is legitimately in flight and is spared). It is a backstop for the
    in-process timeout/cancel handlers — it catches a turn whose handlers never
    ran (e.g. a wedged event loop) or a row a transient DB error left pending.
    """
    interval_min = settings.investigation_reaper_interval_minutes
    age_min = settings.investigation_reaper_minutes
    if interval_min <= 0 or age_min <= 0:
        return
    chat_age = timedelta(seconds=max(int(getattr(settings, "chat_turn_timeout_s", 180)), 1))
    while True:
        await asyncio.sleep(interval_min * 60)
        try:
            async with db_sessionmaker() as db:
                n = await inv_svc.reap_stale_running(db, older_than_minutes=age_min)
            if n:
                _LOGGER.info("reaper: marked %d stale 'running' investigation(s) as error", n)
            async with db_sessionmaker() as db:
                nh = await hunt_svc.reap_stale_running(db, older_than_minutes=age_min)
            if nh:
                _LOGGER.info("reaper: marked %d stale 'running' hunt(s) as error", nh)
            async with db_sessionmaker() as db:
                nb = await bt_svc.reap_stale_running(db, older_than_minutes=age_min)
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


def _eval_nightly_due(
    now: datetime,
    *,
    hour_utc: int,
    last_scheduled_date: str | None,
    latest_snapshot_date: str | None,
) -> bool:
    """True iff the in-app nightly quality eval should run at *now*.

    Runs at most once per UTC day, at the first wake at/after ``hour_utc``.
    Two independent once-per-day guards: the in-memory ``last_scheduled_date``
    (covers failed runs that wrote no snapshot — no retry storm) and the
    durable ``latest_snapshot_date`` (covers restarts after a successful run,
    and a host-cron run that already landed today's point).
    """
    today = now.date().isoformat()
    if last_scheduled_date == today:
        return False
    if now.hour < hour_utc:
        return False
    return latest_snapshot_date != today


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
            try:
                from soc_ai.store import quality as quality_store  # noqa: PLC0415

                async with app.state.db_sessionmaker() as db:
                    rows = await quality_store.recent_snapshots(db, limit=1)
                if rows:
                    latest_snapshot_date = rows[0].created_at.date().isoformat()
            except Exception:
                _LOGGER.warning(
                    "eval-nightly: snapshot freshness check failed (continuing)", exc_info=True
                )
            if not _eval_nightly_due(
                now,
                hour_utc=settings.eval_nightly_hour_utc,
                last_scheduled_date=status.last_scheduled_date,
                latest_snapshot_date=latest_snapshot_date,
            ):
                # A point already landed today (host cron / pre-restart run):
                # consume the day so later wakes skip the DB check too.
                if latest_snapshot_date == now.date().isoformat():
                    status.last_scheduled_date = latest_snapshot_date
                continue
            status.last_scheduled_date = now.date().isoformat()
            status.running = True  # claim the single-flight slot before scheduling
            status._task = asyncio.create_task(_quality_eval_worker(app.state))
        except asyncio.CancelledError:
            raise
        except Exception:
            _LOGGER.exception("eval-nightly scheduler iteration failed; continuing")


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
    then stamps ``last_run_at`` immediately.

    **Single-flight** is per-SCHEDULE, not global: distinct schedules run
    concurrently (the manager keys tasks by hunt_id, so they never collide), but a
    schedule can't re-fire while its own hunt is still running because
    :func:`mark_ran` resets its interval clock the instant it spawns — so the same
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
                    # Reset the interval clock BEFORE spawning: this is the
                    # single-flight guard — even if the spawn is slow or the hunt
                    # runs long, the schedule is no longer "due" next wake.
                    async with app.state.db_sessionmaker() as db:
                        await hs_svc.mark_ran(db, sched.id, now)
                    hunt_id = await manager.start(
                        app.state,
                        objective=sched.objective,
                        started_by="scheduler",
                        kind="scheduled",
                    )
                    if hunt_id is not None:
                        launched += 1
                except asyncio.CancelledError:
                    raise
                except Exception:
                    _LOGGER.exception(
                        "hunt scheduler: schedule id=%s failed to fire; skipping", sched.id
                    )
            if launched:
                _LOGGER.info("hunt scheduler: launched %d scheduled hunt(s)", launched)
        except asyncio.CancelledError:
            raise
        except Exception:
            _LOGGER.exception("hunt scheduler iteration failed; continuing")


def _persist_bootstrap_credential(settings: Any, created_pw: str) -> None:
    """Write the one-shot bootstrap admin password to a locked-down sidecar
    file instead of the shared log stream, and log only a pointer to it.

    setup.sh pre-generates BOOTSTRAP_ADMIN_PASSWORD so this path is off the
    happy path. journald/container logs are often readable by the same
    audience (other analysts, integrations) this credential must stay secret
    from. Mirrors the chmod(0o600) treatment backup.py gives the Ed25519
    signing key sidecar.
    """
    cred_path = settings.soc_ai_data_dir / "bootstrap-admin-password.txt"
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

    # Reap investigations orphaned by the previous process: any row still
    # 'running' at startup can never finish (its background task is gone). Mark
    # them 'interrupted' (NOT 'error') — a clean restart cut them off; they
    # didn't fail. 'interrupted' is re-huntable, so continuous auto-triage (or a
    # manual re-hunt) picks them back up, and the UI shows a benign state instead
    # of a scary "error" in a healthy environment.
    async with db_sessionmaker() as db:
        orphaned = await inv_svc.reap_stale_running(
            db, older_than_minutes=None, status="interrupted"
        )
    if orphaned:
        _LOGGER.info("reaped %d orphaned 'running' investigation(s) at startup", orphaned)

    # Same for hunts orphaned by the previous process (mirror the investigation
    # reaper): a row still 'running' at startup can't finish — mark 'interrupted'.
    async with db_sessionmaker() as db:
        orphaned_hunts = await hunt_svc.reap_stale_running(
            db, older_than_minutes=None, status="interrupted"
        )
    if orphaned_hunts:
        _LOGGER.info("reaped %d orphaned 'running' hunt(s) at startup", orphaned_hunts)

    # Same for backtests orphaned by the previous process: a row still 'running'
    # at startup can't finish (its background replay task died). Mark 'error' —
    # a backtest is a one-shot measurement, not a re-huntable target.
    async with db_sessionmaker() as db:
        orphaned_bt = await bt_svc.reap_stale_running(db, older_than_minutes=None, status="error")
    if orphaned_bt:
        _LOGGER.info("reaped %d orphaned 'running' backtest(s) at startup", orphaned_bt)

    # Same for chat turns: any 'pending' assistant chat row at startup was
    # orphaned by the restart (its background chat task died with the previous
    # process) and would otherwise stay pending — empty — forever.
    async with db_sessionmaker() as db:
        orphaned_chat = await chat_svc.reap_stale_pending(db, older_than=None)
    if orphaned_chat:
        _LOGGER.info("reaped %d orphaned 'pending' chat turn(s) at startup", orphaned_chat)

    return db_sessionmaker


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:  # noqa: PLR0915 — linear app setup
    """Wire up app-scoped clients, tear them down on shutdown."""
    settings = get_settings()
    logging.basicConfig(
        level=settings.log_level,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
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
    autotriage_task = asyncio.create_task(_auto_triage_scheduler_loop(app, settings))
    hunt_schedule_task = asyncio.create_task(_hunt_schedule_loop(app))
    eval_nightly_task = asyncio.create_task(_eval_nightly_loop(app, settings))

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
        autotriage_task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await autotriage_task
        hunt_schedule_task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await hunt_schedule_task
        eval_nightly_task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await eval_nightly_task
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
_DEMO_WRITE_ALLOW: set[tuple[str, str]] = {
    ("POST", "/investigate"),
    ("POST", "/api/v1/hunt"),
}

# Chat + hunt-start POSTs carry a variable id in the path, so they can't live in
# the exact-match set above — match them by pattern. In demo mode these POSTs are
# turned into canned, ZERO-EGRESS replies by the demo branches in the chat/hunt
# managers (soc_ai/webui/chat_manager.py, soc_ai/webui/hunt_console_manager.py);
# ``/api/v1/hunts/chat`` (hunt-start) is wired to a fixture replay in a later task.
# Anchored ``^...$`` so a pattern can only allow the exact chat routes — never a
# broader mutating route that merely contains the substring.
_DEMO_WRITE_ALLOW_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"^/api/v1/investigations/[^/]+/chat$"),
    re.compile(r"^/api/v1/hunts/[^/]+/chat$"),
    re.compile(r"^/api/v1/hunts/chat$"),  # hunt-start (fixture replay wired later)
)


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
            _allowed = (request.method, _path) in _DEMO_WRITE_ALLOW or (
                request.method == "POST" and any(p.match(_path) for p in _DEMO_WRITE_ALLOW_PATTERNS)
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
            if request.url.path == "/healthz":  # never throttle health checks
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
                        content={
                            "detail": {
                                "reason": "rate_limited",
                                "hint": "Too many requests; slow down.",
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
