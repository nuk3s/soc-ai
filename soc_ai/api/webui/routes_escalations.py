"""Check one stranded escalation claim against Security Onion (R5-I5).

``GET /escalations/stranded`` lists the claims that have no answer from
Security Onion. This route is the per-row "Check Security Onion now" on the
Status page. The rule it applies lives in :mod:`soc_ai.webui.escalation_check`.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Annotated, Any

from elastic_transport import TransportError
from elasticsearch import ApiError
from fastapi import Depends, Request
from pydantic import BaseModel, ConfigDict, StringConstraints

from soc_ai.api.deps import get_elastic, get_settings_dep
from soc_ai.api.security import identify_caller
from soc_ai.api.webui._errors import api_error
from soc_ai.api.webui._shared import router
from soc_ai.config import Settings
from soc_ai.so_client.elastic import ElasticClient
from soc_ai.webui import escalation_check as check_svc
from soc_ai.webui.case_links import case_url

_LOGGER = logging.getLogger(__name__)

_AUDIT_SESSION = "escalation-ledger"

# One alert id: an ES ``_id``, at most 512 bytes like the ledger column.
_AlertId = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=512)]


class EscalationCheckIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    alert_id: _AlertId


class EscalationCheckOut(BaseModel):
    """The outcome of one check.

    ``result`` is ``case_found`` (the claim now has its case), ``no_case``
    (soc-ai released the claim), ``waiting`` (the claim stays open) or
    ``already_settled``. ``settled`` is false only for ``waiting``.
    ``message`` is the one sentence the console shows.
    """

    alert_id: str
    result: str
    settled: bool
    message: str
    case_id: str | None = None
    # The case in the Security Onion console. None when the check names no
    # case, and when the settings name no Security Onion host. The Status
    # panel links the case it found (2026-10-20).
    case_url: str | None = None


async def _audit(request: Request, payload: dict[str, Any], *, user: str) -> None:
    """One audit record for a ledger change. Best-effort: the change stands."""
    try:
        audit = getattr(request.app.state, "audit", None)
        if audit is not None:
            await audit.log_kind(_AUDIT_SESSION, "escalation_claim_settled", payload, user=user)
    except Exception:
        _LOGGER.warning("escalation check audit write failed (continuing)", exc_info=True)


@router.post("/escalations/check", response_model=EscalationCheckOut)
async def check_escalation_claim(
    request: Request,
    body: EscalationCheckIn,
    settings: Settings = Depends(get_settings_dep),
    elastic: ElasticClient = Depends(get_elastic),
) -> EscalationCheckOut:
    """Ask Security Onion now about one escalation claim, and settle it on evidence.

    A case link settles the claim with its case. A complete read with no link
    releases the claim, unless the claim is inside the settling window or
    Security Onion marks the alert escalated. Those two stay open.

    404 ``claim_not_found`` when the ledger holds no claim for the alert. 409
    ``check_running`` while a check of the same claim runs. 503
    ``grid_unavailable`` when Security Onion does not answer or answers in
    part. The claim then stays open.

    Analyst-readable like ``GET /escalations/stranded``: the analyst who
    cannot escalate an alert is the person who needs the answer. The check
    writes nothing to Security Onion. A change to the ledger writes an
    ``escalation_claim_settled`` audit record.
    """
    alert_id = body.alert_id
    running = check_svc.checks_running(request.app.state)
    if alert_id in running:
        raise api_error(
            409,
            "check_running",
            "A check of this claim is already running. Wait for its result.",
        )
    running.add(alert_id)
    try:
        async with asyncio.timeout(settings.webui_grid_timeout_s):
            outcome = await check_svc.check_claim(
                request.app.state.db_sessionmaker, elastic, settings, alert_id
            )
    except check_svc.ClaimNotFoundError as exc:
        raise api_error(
            404,
            "claim_not_found",
            "soc-ai holds no escalation claim for this alert. Reload the list.",
        ) from exc
    except (TimeoutError, TransportError, ApiError) as exc:
        _LOGGER.warning("escalation check could not read the grid for alert %s", alert_id)
        raise api_error(
            503,
            "grid_unavailable",
            "The claim stays open. Security Onion did not answer.",
        ) from exc
    finally:
        running.discard(alert_id)

    if outcome.result in (check_svc.RESULT_CASE_FOUND, check_svc.RESULT_NO_CASE):
        await _audit(
            request,
            {"alert_id": alert_id, "result": outcome.result, "case_id": outcome.case_id},
            user=await identify_caller(request),
        )
    return EscalationCheckOut(
        alert_id=outcome.alert_id,
        result=outcome.result,
        settled=outcome.settled,
        message=outcome.message,
        case_id=outcome.case_id,
        case_url=case_url(settings, outcome.case_id) if outcome.case_id else None,
    )
