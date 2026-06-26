"""FastAPI dependency providers - pull lifecycle-managed objects off ``app.state``."""

from __future__ import annotations

from typing import Any

from fastapi import Request

from soc_ai.agent.orchestrator import InvestigationContext
from soc_ai.audit.logger import AuditLogger
from soc_ai.config import Settings
from soc_ai.so_client.auth import SoAuthClient
from soc_ai.so_client.elastic import ElasticClient
from soc_ai.tools._registry import ApprovalGate
from soc_ai.tools.enrichment import MispClient


def get_settings_dep(request: Request) -> Settings:
    return request.app.state.settings  # type: ignore[no-any-return]


def get_auth(request: Request) -> SoAuthClient:
    return request.app.state.auth  # type: ignore[no-any-return]


def get_elastic(request: Request) -> ElasticClient:
    return request.app.state.elastic  # type: ignore[no-any-return]


def get_misp(request: Request) -> MispClient | None:
    return request.app.state.misp  # type: ignore[no-any-return]


def get_gate(request: Request) -> ApprovalGate:
    return request.app.state.gate  # type: ignore[no-any-return]


def get_audit(request: Request) -> AuditLogger:
    return request.app.state.audit  # type: ignore[no-any-return]


def ctx_from_state(state: Any) -> InvestigationContext:
    """Build a fresh :class:`InvestigationContext` from app.state (no Request needed).

    Used by background workers (auto-triage) that hold a reference to
    ``app.state`` rather than a live ``Request``.
    """
    enrichment = state.enrichment
    return InvestigationContext(
        settings=state.settings,
        auth=state.auth,
        elastic=state.elastic,
        misp=state.misp,
        gate=state.gate,
        audit=state.audit,
        blocklist=enrichment.blocklist,
        maxmind=enrichment.maxmind,
        cloud=enrichment.cloud,
        # Thread the store session factory so the Oracle escalation path can
        # resolve the effective internal-identifier set before egress (inc 2c).
        # getattr keeps older app.state shapes / test doubles working.
        db_sessionmaker=getattr(state, "db_sessionmaker", None),
    )


def get_investigation_ctx(request: Request) -> InvestigationContext:
    """Build a fresh :class:`InvestigationContext` per request, sharing app-scoped clients."""
    return ctx_from_state(request.app.state)
