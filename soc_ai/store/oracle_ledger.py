"""Read the Oracle ledger from the stored investigation events.

The orchestrator writes one event per Oracle decision on the run it belongs
to: ``oracle_escalation``, ``oracle_adjudication``, ``oracle_adjudication_failed``
and, with ``oracle_rule_mode=shadow``, ``oracle_shadow``. This module holds
the queries that tally those rows for the console.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from soc_ai.store.auth import utcnow
from soc_ai.store.models import Investigation, InvestigationEvent

SHADOW_KIND = "oracle_shadow"

# Display order of the reasons in the tally: the uncertainty rule's three
# triggers, then the classic rule's three.
_UNCERTAINTY_ORDER = ("confidence_in_band", "template_split", "deep_needs_more_info")
_CLASSIC_ORDER = ("needs_more_info", "malware_non_tp", "below_confidence")


@dataclass(frozen=True)
class ShadowReasonRow:
    """One reason of one rule: how many runs it named, and the overlap.

    ``overlap`` counts the runs of this row that the other rule sends too.
    """

    rule: str
    reason: str
    count: int
    overlap: int


@dataclass(frozen=True)
class ShadowTally:
    """The shadow week in numbers: what each rule sends and where they agree."""

    days: int
    recorded: int
    would_escalate: int
    classic: int
    both: int
    by_reason: list[ShadowReasonRow] = field(default_factory=list)


def _ordered(counter: Counter[str], order: tuple[str, ...]) -> list[str]:
    known = [r for r in order if counter.get(r)]
    extra = sorted(r for r in counter if r not in order)
    return known + extra


def tally_shadow_payloads(payloads: list[dict[str, Any]], *, days: int) -> ShadowTally:
    """Fold ``oracle_shadow`` payloads into a :class:`ShadowTally`."""
    would = 0
    classic = 0
    both = 0
    unc_count: Counter[str] = Counter()
    unc_overlap: Counter[str] = Counter()
    cls_count: Counter[str] = Counter()
    cls_overlap: Counter[str] = Counter()
    for p in payloads:
        unc = p.get("uncertainty_reason")
        cls = p.get("classic_reason")
        unc_reason = str(unc) if unc else ""
        cls_reason = str(cls) if cls else ""
        if unc_reason:
            would += 1
            unc_count[unc_reason] += 1
            if cls_reason:
                unc_overlap[unc_reason] += 1
        if cls_reason:
            classic += 1
            cls_count[cls_reason] += 1
            if unc_reason:
                cls_overlap[cls_reason] += 1
        if unc_reason and cls_reason:
            both += 1
    rows = [
        ShadowReasonRow("uncertainty", r, unc_count[r], unc_overlap[r])
        for r in _ordered(unc_count, _UNCERTAINTY_ORDER)
    ] + [
        ShadowReasonRow("classic", r, cls_count[r], cls_overlap[r])
        for r in _ordered(cls_count, _CLASSIC_ORDER)
    ]
    return ShadowTally(
        days=days,
        recorded=len(payloads),
        would_escalate=would,
        classic=classic,
        both=both,
        by_reason=rows,
    )


async def shadow_tally(db: AsyncSession, *, days: int = 7) -> ShadowTally:
    """Tally the ``oracle_shadow`` rows of the runs created in the last ``days``."""
    since = utcnow() - timedelta(days=days)
    rows = (
        await db.scalars(
            select(InvestigationEvent.payload)
            .join(Investigation, Investigation.id == InvestigationEvent.investigation_id)
            .where(InvestigationEvent.kind == SHADOW_KIND, Investigation.created_at >= since)
        )
    ).all()
    payloads = [p for p in rows if isinstance(p, dict)]
    return tally_shadow_payloads(payloads, days=days)


# The events that say how the Oracle route fared on a run.
ROUTE_EVENT_KINDS = ("oracle_adjudication", "oracle_adjudication_failed", "oracle_skipped")

# A failure that made no call says nothing about the route: the egress guard
# refused the payload, the payload did not serialize, or demo mode blocked it.
_NO_CALL_CLASSES = frozenset({"refused", "serialization", "blocked"})
_NO_CALL_REASONS = frozenset({"residue_refusal", "payload_serialization", "egress_blocked"})


@dataclass(frozen=True)
class RouteOutcome:
    """The newest stored event that says how the Oracle route fared."""

    kind: str
    payload: dict[str, Any]
    run_created_at: datetime | None


async def latest_route_outcome(db: AsyncSession, *, scan_limit: int = 500) -> RouteOutcome | None:
    """The newest answer, call failure or pause skip of the Oracle route, or None.

    Reads the stored events newest first. A failure that made no call (a
    refusal, a serialization failure, a demo block) is passed over. The doctor
    of another process reads the route state here: the breaker itself lives in
    the process that called the Oracle.
    """
    rows = await db.execute(
        select(InvestigationEvent.kind, InvestigationEvent.payload, Investigation.created_at)
        .join(Investigation, Investigation.id == InvestigationEvent.investigation_id)
        .where(InvestigationEvent.kind.in_(ROUTE_EVENT_KINDS))
        .order_by(InvestigationEvent.id.desc())
        .limit(scan_limit)
    )
    for kind, payload, created_at in rows:
        p = payload if isinstance(payload, dict) else {}
        if kind == "oracle_adjudication_failed" and (
            p.get("error_class") in _NO_CALL_CLASSES or p.get("reason") in _NO_CALL_REASONS
        ):
            continue
        return RouteOutcome(kind=str(kind), payload=p, run_created_at=created_at)
    return None


__all__ = [
    "ROUTE_EVENT_KINDS",
    "SHADOW_KIND",
    "RouteOutcome",
    "ShadowReasonRow",
    "ShadowTally",
    "latest_route_outcome",
    "shadow_tally",
    "tally_shadow_payloads",
]
