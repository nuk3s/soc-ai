"""Data sources, workspaces, notifications, current-user (/me) and /health endpoints."""

from __future__ import annotations

import logging
import time
from datetime import timedelta
from typing import Any

from fastapi import Depends, Request
from pydantic import BaseModel, Field

from soc_ai.api.data_sources import DataSourceOut, collect_data_sources
from soc_ai.api.deps import get_settings_dep
from soc_ai.api.webui._shared import (
    _ago,
    open_router,
    require_admin_api,
    router,
)
from soc_ai.config import Settings
from soc_ai.store import auth as auth_svc
from soc_ai.store import hunts as hunts_svc
from soc_ai.store import investigations as inv_svc
from soc_ai.webui import (
    probes,
)
from soc_ai.webui.deps import current_user

_LOGGER = logging.getLogger(__name__)


class DataSourcesOut(BaseModel):
    sources: list[DataSourceOut]


@router.get(
    "/config/data-sources",
    response_model=DataSourcesOut,
    dependencies=[Depends(require_admin_api)],
)
async def get_data_sources(
    settings: Settings = Depends(get_settings_dep),
) -> DataSourcesOut:
    """Every enrichment data source — local feeds + opt-in online lookups — with
    freshness and key/enable status, for the config console's Data Sources panel."""
    return DataSourcesOut(sources=collect_data_sources(settings))


# ── Demo flag (open) ────────────────────────────────────────────────────────


class DemoStatusOut(BaseModel):
    demo: bool


@open_router.get("/demo-status", response_model=DemoStatusOut)
async def demo_status(settings: Settings = Depends(get_settings_dep)) -> DemoStatusOut:
    """Whether this deployment is the public demo (``SOC_AI_DEMO``).

    Deliberately on ``open_router`` (pre-auth): the SPA's honesty banner —
    rendered by both route roots (AppShell and the login screen) — must show on
    EVERY screen under ANY auth config, including before login. Boolean only;
    no secrets, no config.
    """
    return DemoStatusOut(demo=settings.soc_ai_demo)


# ── Shell chrome: workspaces + notifications ───────────────────────────────


class WorkspaceOut(BaseModel):
    name: str
    env: str


class NotificationOut(BaseModel):
    id: str
    tone: str
    title: str
    when: str
    href: str | None = None


@router.get("/workspaces", response_model=list[WorkspaceOut])
async def list_workspaces(settings: Settings = Depends(get_settings_dep)) -> list[WorkspaceOut]:
    host = str(settings.so_host or "Security Onion")
    name = host.replace("https://", "").replace("http://", "").rstrip("/") or "Security Onion"
    return [WorkspaceOut(name=name, env="prod")]


# How far back completed runs/hunts stay in the bell. Long enough to survive a
# shift handover, short enough that the panel is "what happened recently", not
# a history screen. Items are client-dismissible (stable ids → localStorage).
_NOTIF_WINDOW = timedelta(hours=24)


@router.get("/notifications", response_model=list[NotificationOut])
async def list_notifications(request: Request) -> list[NotificationOut]:
    """In-flight runs + last-24h completions (investigations and hunts).

    The bell badge counts exactly this list — it must never advertise an item
    the panel can't show (the dogfood-2026-07-15 "badge=1, panel empty"
    phantom). Completions are durable, dismissible entries rather than
    transient in-flight state that vanishes between polls.
    """
    cutoff = auth_svc.utcnow() - _NOTIF_WINDOW
    out: list[NotificationOut] = []
    async with request.app.state.db_sessionmaker() as db:
        running = await inv_svc.list_recent(db, status="running", limit=20)
        completed = await inv_svc.list_recent(db, status="complete", limit=20)
        hunts_done = await hunts_svc.list_recent(db, status="complete", limit=10, since=cutoff)
    for inv in running:
        out.append(
            NotificationOut(
                id=f"inv:{inv.id}",
                tone="accent",
                title=f"Investigating: {inv.rule_name or inv.id}",
                when=_ago(inv.created_at.isoformat()),
                href=f"/investigation/{inv.id}",
            )
        )
    done: list[NotificationOut] = []
    for inv in completed:
        fin = inv.finished_at
        if fin is None or fin < cutoff:
            continue
        verdict = inv.verdict or "untriaged"
        tone = (
            "danger"
            if verdict == "true_positive"
            else "warn"
            if verdict in ("needs_more_info", "inconclusive")
            else "accent"
        )
        done.append(
            NotificationOut(
                id=f"inv-done:{inv.id}",
                tone=tone,
                title=f"Verdict {verdict}: {inv.rule_name or inv.id}",
                when=_ago(fin.isoformat()),
                href=f"/investigation/{inv.id}",
            )
        )
    for h in hunts_done:
        findings = (h.report or {}).get("findings") or []
        n = len(findings)
        done.append(
            NotificationOut(
                id=f"hunt-done:{h.id}",
                tone="warn" if n else "accent",
                title=f"Hunt finished — {n} finding{'' if n == 1 else 's'}: {h.objective[:80]}",
                when=_ago((h.finished_at or h.created_at).isoformat()),
                href=f"/hunts/{h.id}",
            )
        )
    return (out + done)[:12]


# ── Scheduled maintenance (backup + blocklist cron visibility) ─────────────


class BackupArchiveOut(BaseModel):
    name: str
    size_bytes: int
    modified: str  # tz-aware ISO


class MaintenanceOut(BaseModel):
    backups: list[BackupArchiveOut]
    backups_dir: str
    blocklists_dir: str
    # Newest blocklist file's mtime — when the feeds were last refreshed.
    blocklists_refreshed: str | None = None
    blocklist_files: int = 0


_BACKUP_LIST_CAP = 8


@router.get(
    "/maintenance",
    response_model=MaintenanceOut,
    dependencies=[Depends(require_admin_api)],
)
async def get_maintenance(settings: Settings = Depends(get_settings_dep)) -> MaintenanceOut:
    """Observed maintenance facts for the Config panel.

    The nightly backup/blocklist crons run OUTSIDE the app (host crontab), so
    the product can't promise a schedule — it reports what actually happened:
    the archives sitting in ``<data_dir>/backups`` and the blocklist feeds'
    freshness. Automation the user can't see in the UI doesn't exist (user
    requirement, 2026-07-16). Missing dirs are a normal cold state, never a 500.
    """
    from datetime import UTC, datetime  # noqa: PLC0415

    def _iso(ts: float) -> str:
        return datetime.fromtimestamp(ts, tz=UTC).isoformat()

    backups_dir = settings.soc_ai_data_dir / "backups"
    archives: list[BackupArchiveOut] = []
    try:
        candidates = sorted(
            backups_dir.glob("soc-ai-backup-*.tar.gz"),
            key=lambda p: p.stat().st_mtime,
            reverse=True,
        )
        for p in candidates[:_BACKUP_LIST_CAP]:
            st = p.stat()
            archives.append(
                BackupArchiveOut(name=p.name, size_bytes=st.st_size, modified=_iso(st.st_mtime))
            )
    except OSError:
        pass  # no backups yet — cold state, not an error

    newest: float | None = None
    n_files = 0
    try:
        for p in settings.blocklist_data_dir.iterdir():
            if not p.is_file():
                continue
            n_files += 1
            mt = p.stat().st_mtime
            newest = mt if newest is None or mt > newest else newest
    except OSError:
        pass

    return MaintenanceOut(
        backups=archives,
        backups_dir=str(backups_dir),
        blocklists_dir=str(settings.blocklist_data_dir),
        blocklists_refreshed=_iso(newest) if newest is not None else None,
        blocklist_files=n_files,
    )


# ── Current-user endpoints ────────────────────────────────────────────────


class MeOut(BaseModel):
    username: str
    role: str
    status: str


class SetStatusIn(BaseModel):
    status: str = Field(default="", max_length=120)


_DEV_ME = MeOut(username="analyst", role="admin", status="")


@router.get("/me", response_model=MeOut)
async def get_me(request: Request) -> MeOut:
    """Return the current user's username, role, and status.

    When ``api_auth_required`` is False (dev / lab default) and there is no
    active session, return a sensible dev fallback so the SPA always has a
    user to render.  When auth IS required and there is no session, the
    ``require_api_auth`` dependency already rejected the request with 401
    before this handler runs.
    """
    user = await current_user(request)
    if user is None:
        return _DEV_ME
    return MeOut(username=user.username, role=user.role, status=user.status)


@router.post("/me/status")
async def set_my_status(request: Request, body: SetStatusIn) -> dict[str, str | bool]:
    """Update the current user's status string (trim + cap at 64 chars).

    In dev mode with no session the request is a no-op that echoes back the
    (sanitised) status — nothing is persisted.
    """
    trimmed = body.status.strip()[:64]
    user = await current_user(request)
    if user is None:
        # Dev / no-auth mode: nothing to persist, just echo back.
        return {"ok": True, "status": trimmed}
    async with request.app.state.db_sessionmaker() as db:
        await auth_svc.set_user_status(db, user.id, trimmed)
    return {"ok": True, "status": trimmed}


# ── Upstream health (ES / LLM / PCAP) — drives the live status indicator ───────

_PCAP_PROBE_TTL_S = 300.0  # SSH is heavy; cache the PCAP probe between polls.
# ES + LLM probes are cheap HTTP, but the dashboard polls /health every ~30s and
# several tabs can poll at once — a short TTL keeps a burst of near-simultaneous
# polls from fanning out to the upstreams while still feeling live.
_HEALTH_PROBE_TTL_S = 15.0


class HealthComponentOut(BaseModel):
    ok: bool
    detail: str


class HealthOut(BaseModel):
    es: HealthComponentOut
    llm: HealthComponentOut
    pcap: HealthComponentOut | None = None  # only when pcap_enabled


async def _cached_pcap_probe(state: Any, settings: Settings) -> dict[str, Any]:
    now = time.monotonic()
    cached = getattr(state, "_pcap_probe_cache", None)
    if cached is not None and now - cached[0] < _PCAP_PROBE_TTL_S:
        return cached[1]  # type: ignore[no-any-return]
    result = await probes.probe_pcap(settings)
    state._pcap_probe_cache = (now, result)
    return result


async def _cached_health_probes(state: Any, settings: Settings) -> dict[str, dict[str, Any]]:
    """The ES + LLM probe results, TTL-cached on app state.

    Both are cheap, but a 30s dashboard poll across several tabs would otherwise
    hit ES + the gateway every time; the short TTL collapses those into one
    probe per window. Returns ``{"es": {...}, "llm": {...}}``.
    """
    now = time.monotonic()
    cached = getattr(state, "_health_probe_cache", None)
    if cached is not None and now - cached[0] < _HEALTH_PROBE_TTL_S:
        return cached[1]  # type: ignore[no-any-return]
    result = {
        "es": await probes.probe_es(state.elastic),
        "llm": await probes.probe_llm(settings),
    }
    state._health_probe_cache = (now, result)
    return result


@router.get("/health", response_model=HealthOut)
async def health(
    request: Request,
    settings: Settings = Depends(get_settings_dep),
) -> HealthOut:
    """Live status of the upstreams the UI depends on. ES + LLM are cheap HTTP
    probes (short-TTL cached); PCAP (heavy SSH) is cached longer. Secret-free."""
    probed = await _cached_health_probes(request.app.state, settings)
    out = HealthOut(
        es=HealthComponentOut(**probed["es"]),
        llm=HealthComponentOut(**probed["llm"]),
    )
    if settings.pcap_enabled:
        out.pcap = HealthComponentOut(**await _cached_pcap_probe(request.app.state, settings))
    return out
