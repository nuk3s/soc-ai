"""Request and response schemas for the soc-ai HTTP API."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field


class InvestigateRequest(BaseModel):
    # NOTE: a legacy `session_id` body field is silently ignored (pydantic's
    # default extra="ignore") — the pipeline mints its own session id.
    alert_id: str = Field(min_length=1)


class HealthResponse(BaseModel):
    status: Literal["ok"] = "ok"
    version: str
    so_auth: Literal["kratos", "connect"]
    misp_configured: bool


class FindAlertRequest(BaseModel):
    """Resolve an alert from row-level context (SO frontends don't embed _ids)."""

    rule_uuid: str | None = None
    rule_name: str | None = None
    source_ip: str | None = None
    destination_ip: str | None = None
    source_port: int | None = None
    destination_port: int | None = None
    timestamp: str | None = None  # ISO or any human-readable form; tolerated.
    event_module: str | None = None
    event_dataset: str | None = None
    # Default 1440min (24h) covers SO's typical 10-24h analyst views without
    # requiring the caller to set this explicitly. Override for tighter
    # bounds when the caller knows it.
    max_age_minutes: int = 1440


class FindAlertResponse(BaseModel):
    alert_id: str | None
    alert_index: str | None
    found_via: str
    candidates_seen: int = 0
