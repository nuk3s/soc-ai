"""FastAPI application entry point.

``uv run soc-ai`` boots the API via :func:`main`; ``uvicorn soc_ai.main:app``
boots it directly. The lifespan manager constructs every long-lived dependency
once and tears them down on shutdown.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
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
from soc_ai.store import hunts as hunt_svc
from soc_ai.store import investigations as inv_svc
from soc_ai.store.auth import bootstrap_admin
from soc_ai.store.config_overrides import apply_to_settings, load_overrides
from soc_ai.store.db import make_engine, make_sessionmaker, run_migrations
from soc_ai.store.secret_box import make_secret_box
from soc_ai.tools._registry import ApprovalGate
from soc_ai.tools.enrichment import MispClient

_LOGGER = logging.getLogger(__name__)

# The built React SPA. Shipped to the deploy target alongside the package; absent
# in source checkouts until `npm run build` runs, so serving is best-effort.
FRONTEND_DIST = Path(__file__).resolve().parent.parent / "frontend" / "dist"


class SpaStaticFiles(StaticFiles):
    """StaticFiles that falls back to index.html on 404 so client-side
    (BrowserRouter) deep links like /app/investigation/INV-1 resolve."""

    async def get_response(self, path: str, scope: Scope) -> Response:
        try:
            return await super().get_response(path, scope)
        except StarletteHTTPException as exc:
            if exc.status_code == 404:
                return await super().get_response("index.html", scope)
            raise


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
    # enable fire on the next wake. _last_sweep starts at 0 so the first enabled
    # wake sweeps immediately.
    _last_sweep = 0.0
    while True:
        await asyncio.sleep(60)
        try:
            if not settings.auto_triage_schedule_enabled:
                continue
            interval_min = int(getattr(settings, "auto_triage_schedule_interval_minutes", 5))
            now = time.monotonic()
            if now - _last_sweep < max(60, interval_min * 60):
                continue
            if at.get_status(app.state).active:
                continue  # a sweep (manual or scheduled) is already in flight
            n = await at.start_config_sweep(app.state, started_by="auto-triage:scheduler")
            if n:
                _last_sweep = time.monotonic()
                _LOGGER.info("auto-triage scheduler: launched a sweep of %d target(s)", n)
        except asyncio.CancelledError:
            raise
        except Exception:
            _LOGGER.exception("auto-triage scheduler iteration failed; continuing")


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
        # One-shot bootstrap credential. It lands in journald/container logs, so
        # mark it unmistakably for the operator to change + scrub. setup.sh
        # pre-generates BOOTSTRAP_ADMIN_PASSWORD so this path is off the happy path.
        _LOGGER.warning(
            "BOOTSTRAP CREDENTIAL (change at first login, then scrub this log line): "
            "initial admin user 'admin' password=%s",
            created_pw,
        )

    # Re-apply persisted admin config overrides onto the live settings singleton
    # so operator choices (e.g. Oracle on/off) survive a restart.
    async with db_sessionmaker() as db:
        overrides = await load_overrides(db)
    apply_to_settings(settings, overrides, secret_box=secret_box)
    if overrides:
        _LOGGER.info("applied %d persisted config override(s)", len(overrides))

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

    auth = make_auth(settings)
    elastic = ElasticClient(settings)
    misp = MispClient(settings) if settings.misp_url is not None else None
    gate = ApprovalGate()
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
    app.state.gate = gate
    app.state.audit = audit
    app.state.enrichment = enrichment
    app.state.decision_signer = decision_signer
    app.state.db_engine = db_engine
    app.state.db_sessionmaker = db_sessionmaker

    reaper_task = asyncio.create_task(_reaper_loop(db_sessionmaker, settings))
    discovery_task = asyncio.create_task(_discovery_scheduler_loop(app, settings))
    autotriage_task = asyncio.create_task(_auto_triage_scheduler_loop(app, settings))

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
        from soc_ai.webui import hunt_console_manager as _hcm  # noqa: PLC0415

        _worker_tasks: list[asyncio.Task[Any]] = []
        _at_task = _at.get_status(app.state)._task
        if _at_task is not None:
            _worker_tasks.append(_at_task)
        _bac_task = _bac.get_status(app.state)._task
        if _bac_task is not None:
            _worker_tasks.append(_bac_task)
        _worker_tasks.extend(_hcm.get_manager(app.state)._tasks.values())
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
    # The Tampermonkey userscript runs in the SO web UI's origin and fetches
    # soc-ai cross-origin (the React /app is same-origin and needs no CORS).
    # Scope to CORS_ALLOW_ORIGINS if set, else the SO host; "*" only as a last
    # resort (with a warning). allow_credentials stays False — the cross-origin
    # caller authenticates with a bearer token, not a cookie.
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
            "set CORS_ALLOW_ORIGINS (or SO_HOST) to enable the userscript"
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
