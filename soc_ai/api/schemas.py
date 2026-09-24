"""Request and response schemas for the soc-ai HTTP API."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field


class InvestigateRequest(BaseModel):
    # NOTE: a legacy `session_id` body field is silently ignored (pydantic's
    # default extra="ignore") — the pipeline mints its own session id.
    alert_id: str = Field(min_length=1)


class LivenessResponse(BaseModel):
    """What ``/healthz`` can honestly say: this process answered.

    Named liveness, not health, and it says ``alive`` rather than ``ok``,
    because the container healthcheck polls this endpoint and Docker renders
    the result as the single word *healthy*. A deployment with an unreachable
    grid, a dead model gateway and a green ``docker ps`` is a normal Tuesday
    here, and "healthy" was read as a verdict on the product by people looking
    at exactly that.

    **This endpoint probes nothing, on purpose.** A liveness probe that failed
    on a dependency outage would have the orchestrator restart a container
    whose dependencies are merely down — turning somebody else's outage into a
    restart loop, and taking away the one surface that could have explained it.
    So the status stays unconditional; what changes is that it no longer claims
    something it never measured.

    ``checks`` carries that sentence on the wire rather than only in this
    docstring, because the two places this body is actually read are a paste of
    ``curl .../healthz`` and ``docker inspect``'s health log, and neither of
    them shows a docstring.
    """

    # Unconditional by design (see above) — the process cannot answer when it is
    # not alive, which is the entire signal a liveness probe carries.
    status: Literal["alive"] = "alive"
    checks: str = (
        "none — liveness only, no dependency is probed. "
        "For a health verdict use GET /api/v1/health or `soc-ai doctor`."
    )
    version: str
    # The build inside that version. Both deployments run the image as
    # `:latest`, so the version string cannot tell two builds of one release
    # apart — which is what a bug report and the quality trend both need. Baked
    # in at image build time; null on any build nothing stamped, because a wrong
    # commit is worse than a missing one.
    commit: str | None = None
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
