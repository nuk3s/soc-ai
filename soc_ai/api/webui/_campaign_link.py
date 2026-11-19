"""The campaign of an investigation, as the API states it on the other pages.

The Investigations list, the investigation page, the Alerts groups and the
findings of a hunt each carry ``campaign``: a :class:`CampaignLinkOut`, or
null when the investigation is in no active campaign. The rows come from
:func:`soc_ai.campaigns.service.links_of`, one read for a page.

The model lives in this leaf module, and ``routes_campaigns`` exports it:
the timeline module and the route modules import it with no import cycle.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from pydantic import BaseModel, Field

from soc_ai.api.webui._shared import _iso_utc

if TYPE_CHECKING:
    from collections.abc import Mapping

    from soc_ai.campaigns.service import CampaignLink, HostCampaign


class CampaignLinkOut(BaseModel):
    """The campaign that an investigation is in.

    ``status`` is ``open`` or ``ended``. ``stage`` is the stage that the
    campaign reached: ``reconnaissance``, ``attempt``, ``access``, ``action``
    or ``movement``, or null. ``differs`` is true when the investigation is
    on a session of the campaign and its verdict is no true positive.
    ``decision`` is the decision of the analyst on the campaign: ``closed``,
    ``authorized``, ``case``, or null while the campaign waits. ``state`` is
    the one state that the console shows: the decision when one is in
    force, else the status (:func:`soc_ai.campaigns.service.api_state`).
    """

    id: int
    title: str
    status: str
    stage: str | None = None
    differs: bool = False
    decision: str | None = None
    state: str = ""
    # True for an investigation of an authorized campaign that the
    # authorization does not cover. The action rule reads it, so the card
    # and the count agree: no campaign holds such an investigation. It is no
    # field of the answer.
    beyond: bool = Field(default=False, exclude=True)


class HostCampaignOut(CampaignLinkOut):
    """One active campaign of the machine of a host page.

    ``role`` is ``actor``, ``target`` or ``both``. ``differs`` is true when
    each investigation of the campaign that names the machine has a verdict
    that differs. ``firstEvent`` and ``lastEvent`` are the period of the
    campaign. ``alerts`` counts the alert events of the last grid read, and
    is null before the first read.
    """

    role: str
    firstEvent: str
    lastEvent: str
    alerts: int | None = None
    # The time of the grid read of ``alerts``, and true when the content of
    # the campaign changed after it: the page then states the time (SD5).
    alertsReadAt: str | None = None
    alertsBehind: bool = False
    # The later of ``lastEvent`` and the last alert event of a confirmed rule
    # of the stored grid read: the end of the span that the page states.
    lastActivity: str | None = None


def host_campaign_out(row: HostCampaign) -> HostCampaignOut:
    """The API form of one campaign of a machine."""
    return HostCampaignOut(
        id=row.id,
        title=row.title,
        status=row.status,
        stage=row.stage,
        differs=row.differs,
        decision=row.decision,
        state=row.state,
        role=row.role,
        firstEvent=_iso_utc(row.first_event),
        lastEvent=_iso_utc(row.last_event),
        alerts=row.alerts,
        alertsReadAt=_iso_utc(row.alerts_at) if row.alerts_at is not None else None,
        alertsBehind=row.alerts_behind,
        lastActivity=_iso_utc(row.last_activity),
    )


def link_out(link: CampaignLink | None) -> CampaignLinkOut | None:
    """The API form of one link, or None."""
    if link is None:
        return None
    return CampaignLinkOut(
        id=link.id,
        title=link.title,
        status=link.status,
        stage=link.stage,
        differs=link.differs,
        decision=link.decision,
        state=link.state,
        beyond=link.beyond,
    )


def link_for(links: Mapping[str, CampaignLink], run_id: str | None) -> CampaignLinkOut | None:
    """The API form of the link of one investigation id, or None."""
    return link_out(links.get(run_id)) if run_id else None


class InvestigationCampaignOut(CampaignLinkOut):
    """The campaign of the investigation page, with the time of its decision.

    ``decidedAt`` is when the analyst made the decision in force, ISO-8601
    UTC, or null. The card and the step strip state it: "The analyst closed
    the campaign on {date}. No action waits." (round "decide once" part 2,
    OW4).
    """

    decidedAt: str | None = None


def investigation_link_for(
    links: Mapping[str, CampaignLink], run_id: str | None
) -> InvestigationCampaignOut | None:
    """:func:`link_for` for the investigation page, with ``decidedAt``."""
    link = links.get(run_id) if run_id else None
    base = link_out(link)
    if link is None or base is None:
        return None
    return InvestigationCampaignOut(
        **base.model_dump(),
        beyond=base.beyond,
        decidedAt=_iso_utc(link.decided_at) if link.decided_at is not None else None,
    )


__all__ = [
    "CampaignLinkOut",
    "HostCampaignOut",
    "InvestigationCampaignOut",
    "host_campaign_out",
    "investigation_link_for",
    "link_for",
    "link_out",
]
