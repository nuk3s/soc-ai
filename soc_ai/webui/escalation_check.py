"""Check Security Onion now for one stranded escalation claim (R5-I5).

The escalation ledger claims an alert before soc-ai opens its case. A claim
with no case id is an escalate whose outcome nobody knows. Only the group
escalate compared such a claim with the grid, and only for alerts still in
its group, so a claim whose alert left the queue never settled. The Status
page listed it and could do nothing about it.

:func:`check_claim` asks Security Onion about one claim and applies the rule
the group escalate already applies in ``_reserve``
(:mod:`soc_ai.api.webui.routes_alert_actions`):

* a case link on the grid settles the claim with that case
  (:func:`soc_ai.store.escalations.record_case`);
* a complete read with no link releases the claim
  (:func:`soc_ai.store.escalations.release`), so the alert can be escalated
  again;
* a read that fails, or a read that is not complete, changes nothing.

Two cases keep the claim open where ``_reserve`` would release it, because
this check runs with no escalate of its own behind it. A claim inside the
settling window can belong to an escalate still in flight, and a release would
let a second press open a second case. An alert that Security Onion marks
escalated is on a case that the link read does not show.

The check writes nothing to Security Onion. It reads the case index and the
alert, and it writes only to soc-ai's own ledger.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from soc_ai.config import Settings
from soc_ai.so_client.elastic import ElasticClient
from soc_ai.so_client.fields import get_dotted
from soc_ai.store import escalations as esc_svc
from soc_ai.webui.case_links import case_ids_for_alerts

_LOGGER = logging.getLogger(__name__)

_STATE_ATTR = "_escalation_checks_running"

# The results. ``case_found`` and ``no_case`` change the ledger.
RESULT_CASE_FOUND = "case_found"
RESULT_NO_CASE = "no_case"
RESULT_WAITING = "waiting"
RESULT_ALREADY_SETTLED = "already_settled"


class ClaimNotFoundError(LookupError):
    """The ledger holds no claim for the alert."""


@dataclass(frozen=True)
class ClaimCheck:
    """The outcome of one check, with the sentence the console shows."""

    alert_id: str
    result: str
    settled: bool
    message: str
    case_id: str | None = None


def checks_running(state: Any) -> set[str]:
    """The alert ids with a check in flight, on *app.state*.

    The route refuses a second check of the same claim while one runs. A
    double press must not send two reads, and two settles of one claim must
    not race.
    """
    if not hasattr(state, _STATE_ATTR):
        setattr(state, _STATE_ATTR, set())
    return getattr(state, _STATE_ATTR)  # type: ignore[no-any-return]


async def _alert_marked_escalated(
    elastic: ElasticClient, settings: Settings, alert_id: str
) -> bool:
    """Whether the alert document carries ``event.escalated``.

    False when the alert is no longer on the grid. That alert cannot be on a
    case the link read misses, and it is the claim this check exists for.
    """
    lookup = await elastic.search(
        settings.events_index_pattern,
        {"ids": {"values": [alert_id]}},
        size=1,
        source=["event.escalated"],
    )
    if not lookup.hits:
        return False
    return bool(get_dotted(lookup.hits[0].get("_source") or {}, "event.escalated"))


async def check_claim(
    db_sessionmaker: Any,
    elastic: ElasticClient,
    settings: Settings,
    alert_id: str,
    *,
    now: datetime | None = None,
) -> ClaimCheck:
    """Compare one claim with Security Onion, and settle it on evidence.

    Raises :class:`ClaimNotFoundError` when the ledger holds no claim for the
    alert. A grid failure propagates (``TransportError``, ``ApiError``,
    ``TimeoutError``) before the ledger changes, so the caller answers 503
    and the claim stays open. ``GridPartialResultsError`` is a
    ``TransportError``: an incomplete read is never "no case".
    """
    async with db_sessionmaker() as db:
        claim = await esc_svc.get_claim(db, alert_id)
    if claim is None:
        raise ClaimNotFoundError(alert_id)
    if claim.case_id:
        return ClaimCheck(
            alert_id=alert_id,
            result=RESULT_ALREADY_SETTLED,
            settled=True,
            case_id=claim.case_id,
            message=f"The claim already has case {claim.case_id} from Security Onion.",
        )

    links = await case_ids_for_alerts(elastic, settings, [alert_id])
    case_id = links.get(alert_id)
    if case_id:
        async with db_sessionmaker() as db:
            await esc_svc.record_case(db, alert_id, case_id)
        return ClaimCheck(
            alert_id=alert_id,
            result=RESULT_CASE_FOUND,
            settled=True,
            case_id=case_id,
            message=f"soc-ai found case {case_id} for alert {alert_id}. The claim is settled.",
        )

    current = (now or datetime.now(UTC)).replace(tzinfo=None)
    claimed_at = claim.created_at.replace(tzinfo=None) if claim.created_at else current
    if current - claimed_at < esc_svc.SETTLING:
        minutes = int(esc_svc.SETTLING.total_seconds() // 60)
        return ClaimCheck(
            alert_id=alert_id,
            result=RESULT_WAITING,
            settled=False,
            message=f"The claim stays open. The escalation is less than {minutes} minutes old.",
        )
    if await _alert_marked_escalated(elastic, settings, alert_id):
        return ClaimCheck(
            alert_id=alert_id,
            result=RESULT_WAITING,
            settled=False,
            message=(
                "The claim stays open. Security Onion marks the alert as escalated and shows "
                "no case link."
            ),
        )

    async with db_sessionmaker() as db:
        await esc_svc.release(db, [alert_id])
    _LOGGER.info("escalation check released the claim on alert %s: no case link", alert_id)
    return ClaimCheck(
        alert_id=alert_id,
        result=RESULT_NO_CASE,
        settled=True,
        message="soc-ai released the claim. Security Onion has no case for the alert.",
    )
