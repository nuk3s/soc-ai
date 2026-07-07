"""Data sources, workspaces, notifications, current-user (/me) and /health endpoints."""

from __future__ import annotations

import logging
import time
from typing import Any

from fastapi import Depends, Request
from pydantic import BaseModel, Field

from soc_ai.api.data_sources import DataSourceOut, collect_data_sources
from soc_ai.api.deps import get_settings_dep
from soc_ai.api.webui._shared import (
    _ago,
    require_admin_api,
    router,
)
from soc_ai.config import Settings
from soc_ai.store import auth as auth_svc
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


@router.get("/notifications", response_model=list[NotificationOut])
async def list_notifications(request: Request) -> list[NotificationOut]:
    out: list[NotificationOut] = []
    async with request.app.state.db_sessionmaker() as db:
        running = await inv_svc.list_recent(db, status="running", limit=20)
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
    return out[:12]


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
