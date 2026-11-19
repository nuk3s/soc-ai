"""The commit of a campaign decision whose audit record came first.

A decision that hides work writes its audit record before the commit, so the
trail never misses a change (a close, an authorization, its revoke, an
exclusion, an inclusion, the undo of either, a case and the clear of its
intent). When the store then fails at
the commit, or the decision of another analyst wins a moment before, the
trail holds a record of a change that did not happen. :func:`record_failed`
writes one more record of the ``*_failed`` kind in :data:`FAILED_KIND`, so the
trail states that the change did not happen. That write is best effort: the
answer to the analyst never waits on a second audit failure.
"""

from __future__ import annotations

import logging
from typing import Any

from fastapi import HTTPException, Request
from sqlalchemy.ext.asyncio import AsyncSession

from soc_ai.api.webui._errors import api_error

_LOGGER = logging.getLogger(__name__)

# The record that states a change of the key kind did not reach the store.
# Each value must be a valid AuditKind (soc_ai/audit/schemas.py), or the audit
# log drops it with no warning.
FAILED_KIND: dict[str, str] = {
    "campaign_closed": "campaign_close_failed",
    "campaign_excluded": "campaign_exclude_failed",
    "campaign_included": "campaign_include_failed",
    "campaign_override_undone": "campaign_override_undo_failed",
    "campaign_case_opened": "campaign_case_failed",
    "campaign_case_retry": "campaign_case_failed",
    "authorized_activity_created": "authorized_activity_create_failed",
    "authorized_activity_revoked": "authorized_activity_revoke_failed",
    "rule_decision_made": "rule_decision_failed",
    "rule_decision_ended": "rule_decision_failed",
}


def store_unavailable(action: str) -> HTTPException:
    """The 503 of a decision that the store did not save."""
    return api_error(
        503,
        "store_unavailable",
        f"soc-ai could not save the {action}, so nothing changed. Try again.",
    )


async def record_failed(
    request: Request,
    session_id: str,
    kind: str,
    payload: dict[str, Any],
    *,
    by: str,
    cause: str,
) -> None:
    """Write the record that the change of *kind* did not happen. Best effort."""
    failed = FAILED_KIND[kind]
    try:
        audit = getattr(request.app.state, "audit", None)
        if audit is not None:
            await audit.log_kind(
                session_id, failed, {**payload, "cause": cause}, user=by, mutating=True
            )
    except Exception:
        _LOGGER.warning("%s audit write failed (continuing)", failed, exc_info=True)


async def fail_after_record(
    request: Request,
    db: AsyncSession,
    exc: BaseException,
    session_id: str,
    kind: str,
    payload: dict[str, Any],
    *,
    by: str,
    action: str,
) -> HTTPException:
    """Roll back a failed store write, record the failure, and give the 503 to raise."""
    try:
        await db.rollback()
    except Exception:
        _LOGGER.warning("campaigns: the rollback after a failed %s failed", kind, exc_info=True)
    _LOGGER.warning("campaigns: the store did not save the %s after its record: %s", kind, exc)
    await record_failed(
        request, session_id, kind, payload, by=by, cause=f"store: {type(exc).__name__}"
    )
    return store_unavailable(action)


async def commit_after_record(
    request: Request,
    db: AsyncSession,
    session_id: str,
    kind: str,
    payload: dict[str, Any],
    *,
    by: str,
    action: str,
) -> None:
    """Commit the change whose audit record of *kind* came first. Raises the 503 on a failure."""
    try:
        await db.commit()
    except Exception as exc:
        raise await fail_after_record(
            request, db, exc, session_id, kind, payload, by=by, action=action
        ) from exc
