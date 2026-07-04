"""Internal-identifier discovery scan endpoints + shared scan status object."""

from __future__ import annotations

import asyncio
import logging
from datetime import UTC, datetime
from typing import Any

from fastapi import Depends, Request
from pydantic import BaseModel

from soc_ai.api.webui._shared import (
    require_admin_api,
    router,
)

_LOGGER = logging.getLogger(__name__)

# ── Internal-identifier discovery: scan-now (single-flight) ────────────────────
#
# Learns internal domain suffixes + bare hostnames from ES and upserts them as
# detected internal_identifier rows. Modeled on the auto-triage pattern: a
# background asyncio task with an in-memory status on app.state, single-flight
# (a second POST while a scan runs returns the running status, doesn't start a
# second). Reuses app.state.elastic + app.state.db_sessionmaker.

_DISCOVERY_STATE_ATTR = "_discovery_status"


class _DiscoveryStatus:
    """In-memory status for the discovery scan-now task on app.state."""

    def __init__(self) -> None:
        self.running: bool = False
        self.last_scan: str | None = None
        self.last_summary: dict[str, Any] | None = None
        self._task: asyncio.Task[None] | None = None


def _get_discovery_status(state: Any) -> _DiscoveryStatus:
    if not hasattr(state, _DISCOVERY_STATE_ATTR):
        setattr(state, _DISCOVERY_STATE_ATTR, _DiscoveryStatus())
    return getattr(state, _DISCOVERY_STATE_ATTR)  # type: ignore[no-any-return]


class DiscoveryStatusOut(BaseModel):
    running: bool
    last_scan: str | None = None
    last_summary: dict[str, Any] | None = None
    note: str | None = None


def _discovery_status_out(status: _DiscoveryStatus, note: str | None = None) -> DiscoveryStatusOut:
    return DiscoveryStatusOut(
        running=status.running,
        last_scan=status.last_scan,
        last_summary=status.last_summary,
        note=note,
    )


async def _run_discovery_task(state: Any) -> None:
    """Background worker: run one discovery scan, stash the summary, never raise."""
    from dataclasses import asdict  # noqa: PLC0415 - lazy

    from soc_ai.enrichment.discovery import run_discovery  # noqa: PLC0415 - lazy

    status = _get_discovery_status(state)
    try:
        summary = await run_discovery(state.elastic, state.db_sessionmaker, state.settings)
        status.last_summary = asdict(summary)
    except Exception:
        _LOGGER.exception("discovery: scan-now task failed")
        status.last_summary = {"errors": ["scan failed; see server logs"]}
    finally:
        status.running = False
        status.last_scan = datetime.now(UTC).isoformat()


@router.post(
    "/discovery/scan",
    response_model=DiscoveryStatusOut,
    dependencies=[Depends(require_admin_api)],
)
async def start_discovery_scan(request: Request) -> DiscoveryStatusOut:
    """Launch a background internal-identifier discovery scan (single-flight).

    Poll ``GET /discovery/scan`` for status. A second POST while a scan is in
    flight returns the running status instead of starting a second scan. Returns
    a note when discovery is disabled (nothing is started)."""
    state = request.app.state
    status = _get_discovery_status(state)
    if status.running:
        return _discovery_status_out(status, note="already running")
    if not state.settings.discovery_enabled:
        return _discovery_status_out(status, note="discovery disabled")
    status.running = True  # claim the slot before scheduling
    status._task = asyncio.create_task(_run_discovery_task(state))
    return _discovery_status_out(status, note="started")


@router.get(
    "/discovery/scan",
    response_model=DiscoveryStatusOut,
    dependencies=[Depends(require_admin_api)],
)
async def discovery_scan_status(request: Request) -> DiscoveryStatusOut:
    return _discovery_status_out(_get_discovery_status(request.app.state))
