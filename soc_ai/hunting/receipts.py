"""Receipts: what a shadow hit must bring before the app shows it as a hit.

A missing part does not hide the hit. The hit shows as "could not run" and it
names the missing part. Hiding it would make a shadow week that found a true
positive look like a shadow week that found nothing, which is the one outcome
this layer exists to prevent.

Four parts, from section 5 of the design:

* the matched document ids, and the fields the analytic read;
* the baseline, for a profile analytic;
* a dry run over the last 30 days: how often it fires and on which entities;
* the overlap: the live analytics that already observe the same documents.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from soc_ai.hunting.execute import SpecRun
from soc_ai.store.models import EntityObservation

__all__ = ["DRY_RUN_WINDOW_DAYS", "Receipts", "build_receipts", "overlap_with_live"]

DRY_RUN_WINDOW_DAYS = 30

# How far back an overlap reads. A live analytic that saw the same documents
# yesterday is the overlap an analyst needs; one that saw them last month is
# history, and the documents have usually rolled out of the index anyway.
_OVERLAP_HOURS = 24

# How many entities a dry run names. Past this the list is a population and the
# count above it is the fact.
_MAX_ENTITIES = 20


@dataclass(frozen=True)
class Receipts:
    """The evidence behind one shadow hit, and what is missing from it."""

    matched_ids: list[str]
    matched_fields: list[str]
    dry_run: dict[str, Any] | None
    overlap: list[dict[str, Any]]
    baseline: dict[str, Any] | None
    missing: list[str] = field(default_factory=list)

    @property
    def complete(self) -> bool:
        return not self.missing

    def as_dict(self) -> dict[str, Any]:
        """The shape that rides in the observation's evidence and on the wire."""
        return {
            "matched_ids": self.matched_ids,
            "matched_fields": self.matched_fields,
            "dry_run": self.dry_run,
            "overlap": self.overlap,
            "baseline": self.baseline,
            "complete": self.complete,
            "missing": self.missing,
        }


def build_receipts(
    *,
    matched_ids: Sequence[str],
    matched_fields: Sequence[str],
    dry_run: SpecRun | None,
    overlap: Sequence[dict[str, Any]],
    baseline: dict[str, Any] | None,
    profile: bool,
    requires_dry_run: bool = True,
    requires_matched_ids: bool = True,
) -> Receipts:
    """Assemble the receipts and name every part that could not be brought.

    Both ``requires_`` flags are False for a profile analytic, and for the same
    reason. A profile analytic compiles to no query. It answers from a stored
    baseline, so it may have no document ids to cite and nothing to re-run over 30
    days. Its baseline carries the same evidence both parts would, and
    demanding either would mark every profile hit incomplete forever — which
    reads as a broken analytic rather than as a different kind of one.
    """
    missing: list[str] = []
    ids = [str(i) for i in matched_ids if i]
    if requires_matched_ids and not ids:
        missing.append("matched_ids")
    dry: dict[str, Any] | None = None
    if requires_dry_run:
        if dry_run is None or dry_run.error is not None or dry_run.blind:
            missing.append("dry_run")
        else:
            dry = {
                "window_days": DRY_RUN_WINDOW_DAYS,
                "fires": int(dry_run.matched_docs or 0),
                "entities": sorted({c.scope_key for c in dry_run.candidates})[:_MAX_ENTITIES],
            }
    if profile and not baseline:
        missing.append("baseline")
    return Receipts(
        matched_ids=ids,
        matched_fields=[str(f) for f in matched_fields],
        dry_run=dry,
        overlap=list(overlap),
        baseline=baseline,
        missing=missing,
    )


async def overlap_with_live(
    db: AsyncSession, *, entity_key: str, sample_ids: Sequence[str], now: datetime
) -> list[dict[str, Any]]:
    """The live analytics whose recent observations on this entity share documents.

    An analytic that fires only where a live one already fires adds cost and no
    coverage. Reads live rows only: a second shadow analytic on the same
    documents proves nothing about what the grid already sees.
    """
    wanted = {str(s) for s in sample_ids if s}
    if not wanted:
        return []
    since = (now - timedelta(hours=_OVERLAP_HOURS)).replace(tzinfo=None)
    rows = await db.scalars(
        select(EntityObservation).where(
            EntityObservation.entity_key == entity_key,
            EntityObservation.shadow.is_(False),
            EntityObservation.born_at >= since,
        )
    )
    counts: dict[str, int] = {}
    for row in rows:
        evidence = row.evidence_json if isinstance(row.evidence_json, dict) else {}
        ids = {str(s) for s in (evidence.get("sample_ids") or evidence.get("citations") or [])}
        if evidence.get("anchor_id"):
            ids.add(str(evidence["anchor_id"]))
        shared = len(ids & wanted)
        if shared:
            counts[row.spec_id] = counts.get(row.spec_id, 0) + shared
    return [{"analytic": k, "documents": v} for k, v in sorted(counts.items())]
