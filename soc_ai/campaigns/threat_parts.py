"""The confirmed threats that wait, and the parts of a set of true positives.

Round "decide once" (DC3, 2026-11-17). On production the Dashboard at 7 days
read "12 true positives on 0 hosts", and its link opened 14 rows. Each of the
12 was in a campaign that the analyst had closed, and 2 of the 14 were
superseded. A decision made once came back as open work.

One rule gives the true positives that wait. A true positive investigation
waits when three things hold:

* its verdict stands: it is the latest run of its alert or of its finding,
  and no follow-up answered it
  (:func:`soc_ai.store.investigations.standing_true_positives`);
* no campaign with a decision in force holds it
  (:func:`soc_ai.campaigns.service.held` and
  :func:`soc_ai.campaigns.decisions.in_force`, the rule of Needs you);
* no authorization mark holds it. The Confirmed threats panel lists such a
  run apart, because nothing in it waits on the analyst;
* the analyst did not decide on the investigation itself (round "decide
  once" part 2, OW1): its report holds no analyst resolution, an action that
  the console can execute is still open, or the run has no such action and
  nobody acknowledged or escalated its alert
  (:func:`soc_ai.api.webui.action_rules.analyst_decided`).

So a standing true positive is in exactly one part: ``decided``,
``authorized``, ``handled``, ``earlier`` or ``waits``. Needs you lists each run that
waits and that no campaign holds
(:func:`soc_ai.api.webui.routes_meta.needs_you_runs`). On production on
2026-11-17 this rule gave 16 and the rule of Needs you gave 13: two true
positives held no recommended action, and one held a resolution.

An investigation beyond the authorization of its campaign is not held, so it
waits. An investigation of a campaign with no decision waits too: the
analyst decides on the campaign.

Round 3 part 2, W2. The Dashboard at 30 days read "36 true positives wait: 6
on their own, 30 in 1 campaign". The analyst had closed that campaign on
2026-11-15, and it opened again for 6 new investigations: the close covered
28 of the 30. A standing true positive of a campaign that soc-ai opened again
(new activity, a higher stage, a new machine) whose event is not after the
boundary of :mod:`soc_ai.campaigns.since_decision`, and that would wait, is
in the part ``earlier``: the earlier decision covered it, and it does not
wait. A run that an authorization mark holds stays ``authorized``. A new
true positive of that campaign waits. An "Open again" by the analyst and a
revoke of the authorization end the earlier decision on purpose, so each true
positive of the campaign waits again.

:func:`in_window` reads the true positives of a window. The Dashboard tile,
the Confirmed threats panel and the Investigations list that the tile opens
read it. :func:`split` gives the parts of any set of true positive runs: the
header of the true positives view and the host page read it.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from soc_ai.campaigns import decisions
from soc_ai.campaigns import service as campaign_svc
from soc_ai.campaigns import since_decision as since_svc
from soc_ai.campaigns.facts import chunked
from soc_ai.store import authorized_activity as authorized_svc
from soc_ai.store import investigations as inv_svc
from soc_ai.store.models import CampaignMember, Investigation

PART_WAITS = "waits"
PART_DECIDED = "decided"
PART_AUTHORIZED = "authorized"
# The analyst decided on the investigation itself (OW1).
PART_HANDLED = "handled"
# Two parts of a run whose verdict does not stand (:func:`split`).
PART_SUPERSEDED = "superseded"
PART_OTHER = "other"
# The earlier decision of a campaign that soc-ai opened again covered it (W2).
PART_EARLIER = "earlier"
PARTS = (
    PART_WAITS,
    PART_DECIDED,
    PART_AUTHORIZED,
    PART_HANDLED,
    PART_SUPERSEDED,
    PART_OTHER,
    PART_EARLIER,
)
# The causes of a reopen that the analyst made. Such a reopen ends the
# earlier decision on purpose, so it covers nothing.
_ANALYST_CAUSES = frozenset({decisions.CAUSE_ANALYST, decisions.CAUSE_REVOKED})


def part_of(
    link: campaign_svc.CampaignLink | None,
    mark: Any,
    *,
    handled: bool = False,
    earlier: bool = False,
) -> str:
    """The part of one true positive whose verdict stands. The one rule.

    ``decided`` when a campaign with a decision in force holds it, else
    ``authorized`` when its authorization mark holds, else ``handled`` when
    the analyst decided on the investigation itself, else ``earlier`` when
    the campaign holds it and ``earlier`` is true: the earlier decision of
    the campaign covered it (:func:`earlier_ids`). Else ``waits``. The part
    ``earlier`` takes only a run that would wait, so the other parts keep
    their counts.
    """
    if link is not None and campaign_svc.held(link) and decisions.in_force(link.decision):
        return PART_DECIDED
    if mark is not None and bool(getattr(mark, "holds", False)):
        return PART_AUTHORIZED
    if handled:
        return PART_HANDLED
    if earlier and link is not None and campaign_svc.held(link):
        return PART_EARLIER
    return PART_WAITS


@dataclass(frozen=True)
class Parts:
    """The part of each run, with the reads that gave it."""

    parts: dict[str, str]
    links: dict[str, campaign_svc.CampaignLink] = field(default_factory=dict)
    marks: dict[int, Any] = field(default_factory=dict)
    # The earlier decision of each reopened campaign that covers a run (W2).
    covered: dict[int, since_svc.Covered] = field(default_factory=dict)

    def ids(self, part: str) -> list[str]:
        """The ids of the runs of one part, in no set order."""
        return [run_id for run_id, p in self.parts.items() if p == part]

    def count(self, part: str) -> int:
        return sum(1 for p in self.parts.values() if p == part)

    def decided_campaigns(self) -> dict[int, int]:
        """The count of decided runs of each campaign that holds them."""
        return self._campaigns(PART_DECIDED)

    def earlier_campaigns(self) -> dict[int, int]:
        """The count of the runs of the part ``earlier`` of each reopened campaign."""
        return self._campaigns(PART_EARLIER)

    def _campaigns(self, part: str) -> dict[int, int]:
        out: dict[int, int] = {}
        for run_id in self.ids(part):
            link = self.links.get(run_id)
            if link is not None:
                out[link.id] = out.get(link.id, 0) + 1
        return out


async def earlier_ids(
    db: AsyncSession, links: Mapping[str, campaign_svc.CampaignLink]
) -> tuple[set[str], dict[int, since_svc.Covered]]:
    """The runs that the earlier decision of their reopened campaign covered (W2).

    A run is in the set when a campaign with no decision in force holds it,
    the campaign opened again by a cause of soc-ai, and the event of the run
    in the campaign is not new (:func:`soc_ai.campaigns.since_decision.is_new`).
    One read of the campaigns, one of their changes and one of the members.
    The second value is the earlier decision of each campaign that covers a
    run.
    """
    held = {
        run_id: link
        for run_id, link in links.items()
        if campaign_svc.held(link) and not decisions.in_force(link.decision)
    }
    if not held:
        return set(), {}
    found = await since_svc.covered(db, {link.id for link in held.values()})
    reopened = {cid: c for cid, c in found.items() if c.cause not in _ANALYST_CAUSES}
    if not reopened:
        return set(), {}
    wanted = [run_id for run_id, link in held.items() if link.id in reopened]
    out: set[str] = set()
    for chunk in chunked(sorted(wanted)):
        rows = await db.execute(
            select(
                CampaignMember.run_id, CampaignMember.campaign_id, CampaignMember.event_time
            ).where(CampaignMember.run_id.in_(chunk))
        )
        for run_id, campaign_id, event_time in rows.all():
            cover = reopened.get(int(campaign_id))
            if cover is not None and not since_svc.is_new(event_time, cover.boundary):
                out.add(str(run_id))
    used = {held[run_id].id for run_id in out}
    return out, {cid: c for cid, c in reopened.items() if cid in used}


async def standing_parts(
    db: AsyncSession,
    runs: Sequence[Investigation],
    *,
    state: Any = None,
    handled: set[str] | None = None,
) -> Parts:
    """The part of each run whose verdict stands: three reads for all runs.

    ``handled`` holds the runs on which the analyst decided, when the caller
    read them (:func:`soc_ai.api.webui.routes_meta.action_reads`). Else this
    reads them. ``state`` is the app state: the action rule asks the grid
    through it whether the anchor of a promotion is a Security Onion alert.
    """
    links = await campaign_svc.links_of(db, [inv.id for inv in runs])
    marks = await authorized_svc.marks_for(db, [inv.authorization_id for inv in runs])
    covered_runs, covered = await earlier_ids(db, links)
    if handled is None:
        handled = await handled_ids(db, runs, state=state)
    return Parts(
        parts={
            inv.id: part_of(
                links.get(inv.id),
                marks.get(inv.authorization_id or 0),
                handled=inv.id in handled,
                earlier=inv.id in covered_runs,
            )
            for inv in runs
        },
        links=links,
        marks=marks,
        covered=covered,
    )


async def handled_ids(
    db: AsyncSession, runs: Sequence[Investigation], *, state: Any = None
) -> set[str]:
    """The ids of the runs on which the analyst decided (the part ``handled``).

    The rule is :func:`soc_ai.api.webui.action_rules.analyst_decided`. The
    read of the action records lives with the needs-you count, so the count,
    the list and this part read one function.
    """
    from soc_ai.api.webui import routes_meta  # noqa: PLC0415 - the API layer reads the records

    if not runs:
        return set()
    return (await routes_meta.action_reads(db, runs, state=state)).handled


@dataclass(frozen=True)
class WindowThreats:
    """The true positives that stand in a window and the part of each.

    ``runs`` holds them, the newest event first. ``total`` counts them, also
    past the scan limit of the read.
    """

    runs: list[Investigation]
    total: int
    parts: Parts

    def waiting(self) -> list[Investigation]:
        return [inv for inv in self.runs if self.parts.parts.get(inv.id) == PART_WAITS]


async def in_window(
    db: AsyncSession, *, since: datetime, until: datetime, state: Any = None
) -> WindowThreats:
    """The true positives that stand in a window, each with its part.

    ``since`` and ``until`` bound the time of the event (naive UTC,
    inclusive), as in :func:`soc_ai.store.investigations.standing_true_positives`.
    ``state`` is as in :func:`standing_parts`.
    """
    runs, total = await inv_svc.standing_true_positives(db, since=since, until=until)
    return WindowThreats(runs=runs, total=total, parts=await standing_parts(db, runs, state=state))


async def split(db: AsyncSession, run_ids: Iterable[str], *, state: Any = None) -> Parts:
    """The part of each true positive run of a set.

    A run whose verdict does not stand is ``superseded`` or ``other``
    (:func:`soc_ai.store.investigations.standing_split`). Each other run
    has the part of :func:`part_of`.
    """
    found = await inv_svc.standing_split(db, run_ids)
    parts = await standing_parts(db, found.standing, state=state)
    merged: dict[str, str] = dict(parts.parts)
    merged.update(dict.fromkeys(found.superseded, PART_SUPERSEDED))
    merged.update(dict.fromkeys(found.other, PART_OTHER))
    return Parts(parts=merged, links=parts.links, marks=parts.marks, covered=parts.covered)


def counts(parts: Mapping[str, str]) -> dict[str, int]:
    """The count of each part, every part named."""
    out = dict.fromkeys(PARTS, 0)
    for part in parts.values():
        out[part] = out.get(part, 0) + 1
    return out


__all__ = [
    "PARTS",
    "PART_AUTHORIZED",
    "PART_DECIDED",
    "PART_EARLIER",
    "PART_HANDLED",
    "PART_OTHER",
    "PART_SUPERSEDED",
    "PART_WAITS",
    "Parts",
    "WindowThreats",
    "counts",
    "earlier_ids",
    "handled_ids",
    "in_window",
    "part_of",
    "split",
    "standing_parts",
]
