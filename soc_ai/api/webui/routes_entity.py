"""Entity pivot page (E3.5): a read-model answering "what do we know about <host>".

``GET /entity/{value}`` merges an entity's investigations (``src_ip``/``dest_ip``
match) and hunt findings (whose ``hosts[]`` names it) into ONE time-sorted
timeline, newest first — so clicking any host chip lands a single screen with
that box's history (investigations, verdicts, hunt findings) instead of opening
N runs by hand.

Pure read-model: no new writes, no migration. It reuses two BOUNDED queries —
:func:`soc_ai.store.investigations.for_entity` and
:func:`soc_ai.store.hunts.findings_for_entity` (the latter scans the last N hunt
reports; see its docstring). Analyst-readable (the blanket ``router`` auth), NOT
admin-only.
"""

from __future__ import annotations

import ipaddress
import logging
from typing import Literal

from fastapi import Request
from pydantic import BaseModel

from soc_ai.api.webui._shared import (
    _iso_utc,
    _sev,
    _verdict,
    router,
)
from soc_ai.store import hunts as hunt_svc
from soc_ai.store import investigations as inv_svc

_LOGGER = logging.getLogger(__name__)

# Bounds for the two read-model queries. The investigation query is index-friendly
# (low-cardinality src/dst equality); the hunt-findings scan reads report JSON in
# Python, so its bound is the real guardrail (see findings_for_entity).
_INV_LIMIT = 50
_HUNT_SCAN_LIMIT = 100


class EntityTimelineItem(BaseModel):
    # One merged timeline entry — an investigation OR a hunt finding for this
    # entity. ``ts`` is a tz-aware ISO string so the browser localizes it (naive →
    # parsed as local time). ``link`` is the in-app SPA path to open the source.
    ts: str
    kind: Literal["investigation", "hunt_finding"]
    title: str
    # Investigation-only fields.
    verdict: str | None = None
    confidence: float | None = None
    # Hunt-finding-only fields.
    severity: str | None = None
    category: str | None = None
    link: str


class EntitySummaryOut(BaseModel):
    investigationCount: int = 0
    huntFindingCount: int = 0
    # The verdict of the most recent investigation touching this entity (if any) —
    # a one-glance "current disposition of this box".
    latestVerdict: str | None = None


class EntityOut(BaseModel):
    value: str
    # Cheap classification: parseable as an IP → "ip", else "host". "unknown" is
    # reserved for an empty/blank value the router would never route to.
    kind: Literal["ip", "host", "unknown"]
    timeline: list[EntityTimelineItem] = []
    summary: EntitySummaryOut = EntitySummaryOut()


def _classify(value: str) -> Literal["ip", "host", "unknown"]:
    """IP if it parses as an IPv4/IPv6 address, else host. Blank → unknown."""
    if not value.strip():
        return "unknown"
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return "host"
    return "ip"


@router.get("/entity/{value}", response_model=EntityOut)
async def get_entity(request: Request, value: str) -> EntityOut:
    """One screen of an entity's history: its investigations + hunt findings,
    merged and sorted newest-first. An entity we know nothing about returns an
    empty timeline (200, not 404) — "no history" is a valid answer to look at.
    """
    async with request.app.state.db_sessionmaker() as db:
        investigations = await inv_svc.for_entity(db, value, limit=_INV_LIMIT)
        findings = await hunt_svc.findings_for_entity(db, value, scan_limit=_HUNT_SCAN_LIMIT)

    items: list[EntityTimelineItem] = []
    for inv in investigations:
        items.append(
            EntityTimelineItem(
                ts=_iso_utc(inv.created_at),
                kind="investigation",
                title=inv.rule_name or inv.summary or "Investigation",
                verdict=_verdict(inv.verdict),
                confidence=inv.confidence,
                link=f"/app/investigation/{inv.id}",
            )
        )
    for f in findings:
        items.append(
            EntityTimelineItem(
                ts=_iso_utc(f["ts"]),
                kind="hunt_finding",
                title=f["title"] or f["hunt_objective"] or "Hunt finding",
                severity=_sev(f["severity"]),
                category=f["category"],
                link=f"/app/hunts/{f['hunt_id']}",
            )
        )
    # Merge newest-first. ``ts`` is a tz-aware ISO string; a blank (no timestamp)
    # sorts last. String sort of ISO-8601 is chronological.
    items.sort(key=lambda it: it.ts, reverse=True)

    return EntityOut(
        value=value,
        kind=_classify(value),
        timeline=items,
        summary=EntitySummaryOut(
            investigationCount=len(investigations),
            huntFindingCount=len(findings),
            # investigations came back newest-first from for_entity.
            latestVerdict=(_verdict(investigations[0].verdict) if investigations else None),
        ),
    )
