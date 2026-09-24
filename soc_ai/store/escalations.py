"""Store helpers for the alert escalation ledger.

One row per alert soc-ai has escalated to a Security Onion case. The ledger is
soc-ai's own record, not a reading of the grid: Security Onion writes nothing
on the alert when soc-ai attaches it to a case, so there is no flag on the
document to trust, and its case index is a refreshed read that lags the write.

The order of operations is what makes a repeated press safe, and EVERY path
that opens a case follows it — the group escalate and the single-alert escalate
an analyst runs from an investigation alike:

1. :func:`claim` inserts a row per alert. The unique index on ``alert_id`` means
   the insert either succeeds or tells you somebody already holds the alert, in
   one round trip, with no window between the check and the write.
2. The case is opened.
3. :func:`record_case` writes the case id onto the claim, or :func:`release`
   drops it when Security Onion is known to have opened nothing.

There is deliberately no helper for recording a case that was opened WITHOUT
claiming first. One existed for the single-alert path, on the reasoning that it
had idempotency of its own and did not need to reserve anything; that
idempotency was keyed to one investigation and one action, so it could not see a
group escalate over the same alert, and the group escalate could not see it
either until the case was already open. Both presses passed their own check and
Security Onion ended with two cases on one alert. A post-hoc record is not a
guard, and leaving the helper in place is an invitation to write the next
escalate path the same way.

A claim with no case id is an escalate whose outcome nobody knows: the request
may have created a case and then failed on the attach, or failed before
anything was written. Callers reconcile those against the grid's own case links
rather than guessing, which is what :func:`unresolved` is for.

That reconciliation is lazy and press-scoped: it happens only when somebody
presses escalate on a group that happens to contain the same alert, and only
when the grid answers. So an unreconciled claim is not self-healing. It sits
there holding the unique index, refusing every future escalate of that alert,
and until :func:`stranded` there was no way to enumerate the table at all —
every reader here is keyed by an explicit list of alert ids, which is fine for
the press path and useless for the question "what is stuck".
"""

from __future__ import annotations

from datetime import datetime, timedelta

from sqlalchemy import delete, func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from soc_ai.store.models import AlertEscalation

# How long a claim is allowed to be open before it counts as stranded.
#
# Not zero, because the ledger is deliberately claim-first: every escalate
# writes a row with no case id and fills it in a moment later, so a window of
# zero would report the healthy path as broken on every press. Not hours
# either, because the failures this exists to show — a gateway timeout, a grid
# that took the create and refused the attach — resolve or do not resolve
# inside one request. Fifteen minutes is comfortably longer than any escalate
# and short enough that a stuck claim is on screen the same shift it happened.
SETTLING = timedelta(minutes=15)

# How many stranded claims one read returns. The count is reported separately
# and is NOT len(rows): a surface that showed twenty rows and called it twenty
# would under-report a ledger with two hundred stuck claims, which is the same
# silent-cap failure this list exists to expose in the first place.
STRANDED_LIMIT = 50


async def claim(
    db: AsyncSession, alert_ids: list[str], *, actor: str = "unknown"
) -> tuple[list[str], list[str]]:
    """Claim ``alert_ids`` for escalation. Returns ``(claimed, already_held)``.

    An id in ``already_held`` has a row somebody else wrote, so this call must not
    open a case for it. Each insert runs in its own savepoint so one collision
    does not roll back the claims around it.

    Preserves the caller's order and ignores duplicates within one call: the
    same alert asked for twice is claimed once and reported once.
    """
    claimed: list[str] = []
    already: list[str] = []
    for alert_id in dict.fromkeys(i for i in alert_ids if i):
        try:
            async with db.begin_nested():
                db.add(AlertEscalation(alert_id=alert_id, escalated_by=actor))
        except IntegrityError:
            already.append(alert_id)
        else:
            claimed.append(alert_id)
    await db.commit()
    return claimed, already


async def record_case(db: AsyncSession, alert_id: str, case_id: str) -> None:
    """Write the opened case's id onto an existing claim.

    A no-op when the claim is gone or already carries a case id: the first case
    an alert reached is the one the ledger keeps, so a later duplicate (opened
    before this table existed, or by a path that does not claim) cannot
    overwrite the answer a skip is based on.
    """
    row = await db.scalar(select(AlertEscalation).where(AlertEscalation.alert_id == alert_id))
    if row is None or row.case_id:
        return
    row.case_id = case_id
    await db.commit()


async def release(db: AsyncSession, alert_ids: list[str]) -> None:
    """Drop claims for ``alert_ids`` that never became a case.

    Only for ids the caller has positive evidence about, meaning the grid shows no
    link document for them. Releasing on a bare write failure would re-open the
    duplicate: a request can fail after Security Onion has already created the
    case.
    """
    ids = [i for i in dict.fromkeys(alert_ids) if i]
    if not ids:
        return
    await db.execute(delete(AlertEscalation).where(AlertEscalation.alert_id.in_(ids)))
    await db.commit()


async def cases_for_alerts(db: AsyncSession, alert_ids: list[str]) -> dict[str, str | None]:
    """Map claimed alerts to their case id (``None`` while the outcome is open).

    An alert absent from the mapping has never been claimed here. Present with a
    ``None`` value means claimed but unresolved: see :func:`unresolved`.
    """
    ids = [i for i in dict.fromkeys(alert_ids) if i]
    if not ids:
        return {}
    rows = (
        await db.scalars(select(AlertEscalation).where(AlertEscalation.alert_id.in_(ids)))
    ).all()
    return {row.alert_id: row.case_id for row in rows}


def unresolved(claims: dict[str, str | None]) -> list[str]:
    """The claimed alerts whose case id is still unknown."""
    return [alert_id for alert_id, case_id in claims.items() if not case_id]


async def stranded(
    db: AsyncSession,
    *,
    now: datetime,
    settling: timedelta = SETTLING,
    limit: int = STRANDED_LIMIT,
) -> tuple[list[AlertEscalation], int]:
    """Open claims older than ``settling``, oldest first, and how many there are.

    The only reader in this module that is not keyed by an explicit list of
    alert ids, and it exists because every other one is. The press path knows
    which alerts it is about; nobody knew what the table was holding.

    Oldest first rather than newest: a stranded claim does not get better with
    age, and the one stuck longest is the one whose alert has been
    unescalatable longest. Newest-first would put the claims most likely to
    still resolve on their own at the top and push that one off the bottom of
    the cap.

    The count is a separate query over the whole matching set, not
    ``len(rows)``. Reporting the truncated length as the total would be the
    same under-report this surface exists to end.
    """
    cutoff = now - settling
    where = (AlertEscalation.case_id.is_(None)) & (AlertEscalation.created_at <= cutoff)
    rows = list(
        (
            await db.scalars(
                select(AlertEscalation)
                .where(where)
                .order_by(AlertEscalation.created_at.asc(), AlertEscalation.id.asc())
                .limit(limit)
            )
        ).all()
    )
    total = int(
        await db.scalar(select(func.count()).select_from(AlertEscalation).where(where)) or 0
    )
    return rows, total
