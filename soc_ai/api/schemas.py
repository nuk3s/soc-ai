"""Request and response schemas for the soc-ai HTTP API."""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field


class InvestigateRequest(BaseModel):
    alert_id: str = Field(min_length=1)
    session_id: str | None = None


class ApproveRequest(BaseModel):
    token: str = Field(min_length=1)
    approved: bool
    reason: str | None = None


class ApproveResponse(BaseModel):
    status: Literal["executed", "rejected", "already_decided"]
    result: dict[str, Any] | None = None
    error: str | None = None


class HealthResponse(BaseModel):
    status: Literal["ok"] = "ok"
    version: str
    so_auth: Literal["kratos", "connect"]
    misp_configured: bool
    pending_approvals: int


class SessionInfoResponse(BaseModel):
    """Snapshot of an in-flight investigation's pending approvals."""

    session_id: str
    pending_approvals: list[dict[str, Any]]


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
