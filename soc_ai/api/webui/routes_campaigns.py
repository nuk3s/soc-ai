"""Campaigns: one attack as a set of investigations that proven links join.

``GET /campaigns`` lists the active campaigns, the newest last event first.
``GET /campaigns/{id}`` gives one campaign with its sections: the
authorizations that member investigations match, the stage ladder, the
parties, the waves of each actor, the members with the evidence of each link,
the related investigations and documents, the detection record, the arrows of
the attack graph, and the events of the grid between the machines.

Both routes run :func:`soc_ai.campaigns.service.ensure_fresh` first. It
rebuilds the campaigns when the store changed since the last rebuild. When
the rebuild fails, the answer holds the stored campaigns and ``stale`` is
true. The detail route then runs
:func:`soc_ai.campaigns.service.refresh_events`. It reads the grid when the
stored events are due, and a failed read keeps the stored events. Code
decides each field. The model writes none.
"""

from __future__ import annotations

import contextlib
import logging
from collections.abc import Sequence
from datetime import UTC, datetime, timedelta
from typing import Any, Literal

from fastapi import BackgroundTasks, Depends, Request
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from soc_ai.agent import authorized_activity as authorized_decision
from soc_ai.api.deps import get_elastic, get_settings_dep
from soc_ai.api.security import identify_caller
from soc_ai.api.webui._campaign_link import CampaignLinkOut, link_out
from soc_ai.api.webui._decision_commit import (
    commit_after_record,
    fail_after_record,
    record_failed,
    store_unavailable,
)
from soc_ai.api.webui._errors import api_error
from soc_ai.api.webui._shared import _iso_utc, require_admin_api, router
from soc_ai.campaigns import authorization as campaign_auth
from soc_ai.campaigns import case as campaign_case
from soc_ai.campaigns import decisions, finding_names, lead_tags
from soc_ai.campaigns import service as campaign_svc
from soc_ai.campaigns import since_decision as since_svc
from soc_ai.campaigns.events import SOURCE_GRID, CampaignEvents
from soc_ai.campaigns.facts import chunked
from soc_ai.campaigns.ladder import HeldBy, held_by
from soc_ai.campaigns.types import KIND_FINDING, StageStep
from soc_ai.config import Settings
from soc_ai.hunting import campaign_hunt, hunt_answers
from soc_ai.secret_scrub import scrub_secrets
from soc_ai.so_client.elastic import ElasticClient
from soc_ai.store import authorized_activity as authorized_svc
from soc_ai.store import leads as leads_store
from soc_ai.store.auth import utcnow
from soc_ai.store.models import Campaign, CampaignMember, CampaignRunOverride, Investigation

_LOGGER = logging.getLogger(__name__)

# The session id of the audit records of a campaign decision.
AUDIT_SESSION = "campaigns"


class PartyBriefOut(BaseModel):
    """A party in short. ``name`` is null when the Hosts data names no machine,
    and ``address`` is the first address of the party."""

    machineKey: str
    name: str | None = None
    address: str | None = None


class RowAuthorizationOut(BaseModel):
    """The authorization of a campaign in short. ``state`` is ``active``,
    ``expired`` or ``revoked``."""

    expiresAt: str
    state: str


class CampaignRowCaseOut(BaseModel):
    """The case of a campaign row: the time of the press that opened it."""

    openedAt: str


class SinceMachineOut(BaseModel):
    """One machine of the new investigations: its key, its name and its first address."""

    machineKey: str
    name: str | None = None
    address: str | None = None


class EarlierDecisionOut(BaseModel):
    """The decision that the reopen ended. ``decision`` is ``closed``,
    ``authorized`` or ``case``. ``label`` is the words of the reason of a
    close, or the label of an authorization. ``noteKnown`` is false for a
    decision of a change of an earlier release: its note is unknown."""

    decision: str
    reason: str | None = None
    label: str | None = None
    note: str | None = None
    noteKnown: bool = True
    by: str | None = None
    at: str | None = None


class VerdictCountOut(BaseModel):
    verdict: str
    count: int


class SinceHoldingOut(BaseModel):
    """One authorization that holds new investigations (W1). ``state`` is
    ``active``, ``expired`` or ``revoked``."""

    id: int
    label: str
    state: str
    expiresAt: str | None = None
    investigations: int = 0


class SinceHuntOut(BaseModel):
    """The hunt that the reopen started (W1). ``outcome`` holds the words of
    the hunt page, for example "1 confirmed · 1 false positive · 0 not judged
    · of 2 threat findings". It is null while the hunt runs."""

    id: str
    startedAt: str
    status: str
    outcome: str | None = None


class SinceDecisionOut(BaseModel):
    """What is new in a campaign since the decision that a reopen ended (SD2).

    ``cause`` is ``activity``, ``stage``, ``party``, ``analyst`` or
    ``revoked``. ``boundary`` is the last event of the basis of the earlier
    decision (``boundarySource`` ``basis``), else the time of the decision
    (``decision``). ``runIds`` are the investigations of the campaign with an
    event after the boundary, the oldest first, with any verdict, and
    ``investigations`` counts them. ``verdicts`` counts them by verdict, the
    true positives first. ``authorized`` counts those whose authorization
    mark holds. ``rules`` counts the distinct rules of the new alert
    investigations. ``stage`` is the highest stage among them, and
    ``stageBefore`` and ``stageNow`` are the stage of the campaign at the
    decision and now. ``newMachines`` names each machine that the earlier
    decision did not hold.

    ``outsideTruePositives`` counts the new true positives that no
    authorization holds, and ``outsideNames`` holds their rule names.
    ``authorizations`` lists each authorization that holds new
    investigations, the most first. ``reopenHunt`` is the hunt that the
    reopen started, else null (W1).
    """

    earlier: EarlierDecisionOut
    cause: str
    reopenedAt: str
    reopenedBy: str | None = None
    boundary: str
    boundarySource: str
    runIds: list[str] = Field(default_factory=list)
    investigations: int = 0
    verdicts: list[VerdictCountOut] = Field(default_factory=list)
    authorized: int = 0
    actors: list[SinceMachineOut] = Field(default_factory=list)
    targets: list[SinceMachineOut] = Field(default_factory=list)
    rules: int = 0
    firstEvent: str | None = None
    lastEvent: str | None = None
    stage: str | None = None
    stageBefore: str | None = None
    stageNow: str | None = None
    stageRose: bool = False
    newMachines: list[str] = Field(default_factory=list)
    outsideTruePositives: int = 0
    outsideNames: list[str] = Field(default_factory=list)
    authorizations: list[SinceHoldingOut] = Field(default_factory=list)
    reopenHunt: SinceHuntOut | None = None
    # The alert events of the confirmed rules after the newest investigation
    # event, or after the boundary when it is later (G2): the count, the
    # count of the rules and the time of the last. They take the verdict of
    # an earlier investigation.
    laterAlerts: int = 0
    laterRules: int = 0
    laterLastAt: str | None = None


def since_out(since: since_svc.SinceDecision | None) -> SinceDecisionOut | None:
    """The API form of :func:`since_svc.since_decisions` for one campaign, or None."""
    if since is None:
        return None
    earlier = since.earlier

    def machine(m: since_svc.Machine) -> SinceMachineOut:
        return SinceMachineOut(machineKey=m.key, name=m.name, address=m.address)

    return SinceDecisionOut(
        earlier=EarlierDecisionOut(
            decision=earlier.decision,
            reason=earlier.reason,
            label=earlier.label,
            note=earlier.note,
            noteKnown=earlier.note_known,
            by=earlier.by,
            at=_iso(earlier.at),
        ),
        cause=since.cause,
        reopenedAt=_iso_utc(since.reopened_at),
        reopenedBy=since.reopened_by,
        boundary=_iso_utc(since.boundary),
        boundarySource=since.boundary_source,
        runIds=list(since.run_ids),
        investigations=since.investigations,
        verdicts=[VerdictCountOut(verdict=v, count=n) for v, n in since.verdicts],
        authorized=since.authorized,
        actors=[machine(m) for m in since.actors],
        targets=[machine(m) for m in since.targets],
        rules=since.rules,
        firstEvent=_iso(since.first_event),
        lastEvent=_iso(since.last_event),
        stage=since.stage,
        stageBefore=since.stage_before,
        stageNow=since.stage_now,
        stageRose=since.stage_rose,
        newMachines=list(since.new_machines),
        outsideTruePositives=since.outside,
        outsideNames=[scrub_secrets(name) for name in since.outside_names],
        authorizations=[
            SinceHoldingOut(
                id=h.id,
                label=scrub_secrets(h.label),
                state=h.state,
                expiresAt=_iso(h.expires_at),
                investigations=h.investigations,
            )
            for h in since.holding
        ],
        laterAlerts=since.later_alerts,
        laterRules=since.later_rules,
        laterLastAt=_iso(since.later_last_at),
    )


class CampaignRowOut(BaseModel):
    """One campaign of the list. ``targets`` names at most three targets, and
    ``targetsMore`` counts the rest. ``status`` is ``open`` or ``ended``.
    ``members`` counts the true positive member investigations. ``alerts``
    counts the alert events of the last grid read, and is null before the
    first read."""

    id: int
    title: str
    status: str
    stage: str | None = None
    actors: list[PartyBriefOut] = Field(default_factory=list)
    targets: list[PartyBriefOut] = Field(default_factory=list)
    targetsMore: int = 0
    firstEvent: str
    lastEvent: str
    members: int
    alerts: int | None = None
    # ``closed``, ``authorized``, ``case`` or null. ``waitsSince`` is null
    # when the campaign holds a decision.
    decision: str | None = None
    waitsSince: str | None = None
    # The one state that the console shows: the decision in force, else the
    # status (``campaign_svc.api_state``).
    state: str = ""
    # The authorization that the campaign names, or null. ``beyond`` counts
    # the true positive investigations beyond it, and is 0 with none.
    authorization: RowAuthorizationOut | None = None
    beyond: int = 0
    # The case of a campaign with the decision ``case``, else null.
    case: CampaignRowCaseOut | None = None
    # What is new since the decision that a reopen ended, else null.
    sinceDecision: SinceDecisionOut | None = None
    # The time of the grid read of ``alerts``, and true when the content of
    # the campaign changed after it: the count can be behind, and the console
    # states the time of the read (SD5).
    alertsReadAt: str | None = None
    alertsBehind: bool = False
    # The last alert event of a confirmed rule of the stored grid read, else
    # null. ``lastActivity`` is the later of it and ``lastEvent``: each
    # surface states the span of the campaign to it.
    lastAlertAt: str | None = None
    lastActivity: str | None = None


class CampaignsOut(BaseModel):
    rows: list[CampaignRowOut] = Field(default_factory=list)
    total: int = 0
    # True when the rebuild failed and the rows are the stored ones.
    stale: bool = False


class EarlierCampaignOut(BaseModel):
    id: int
    title: str


class CampaignAuthorizationOut(BaseModel):
    """An authorization that member investigations matched. ``state`` is
    ``active``, ``expired`` or ``revoked``."""

    id: int
    label: str
    state: str
    expiresAt: str
    memberRuns: int


class StageEvidenceOut(BaseModel):
    """The record that proves a stage: its document id, its label and its time."""

    documentId: str
    label: str
    at: str | None = None


class StageHeldOut(BaseModel):
    """A stage held by ``at``: the later stage ``stage`` has proof at that time."""

    at: str
    stage: str


class StageStepOut(BaseModel):
    """One stage of the ladder. ``headline`` states what happened, in the
    sentence of the investigation that proves the stage. ``evidence`` is the
    record that proves the stage, or null when that investigation holds no
    document. ``heldBy`` is set when a later stage that needs this stage has
    earlier proof: the stage then held by that time, with or without proof
    of its own (:mod:`soc_ai.campaigns.ladder`)."""

    stage: str
    reached: bool
    firstAt: str | None = None
    members: int = 0
    proofRunId: str | None = None
    proofDocumentId: str | None = None
    headline: str | None = None
    evidence: StageEvidenceOut | None = None
    heldBy: StageHeldOut | None = None


class CampaignPartyOut(BaseModel):
    """One machine of the campaign. ``join`` is ``agent``, ``dhcp`` or
    ``network``. ``beyond`` is true for a target that only a target acted on."""

    machineKey: str
    name: str | None = None
    role: str
    addresses: list[str] = Field(default_factory=list)
    join: str | None = None
    hasAgent: bool = False
    firstEvent: str | None = None
    lastEvent: str | None = None
    memberRuns: int = 0
    beyond: bool = False


class WaveOut(BaseModel):
    n: int
    start: str
    end: str
    events: int


class ActorWavesOut(BaseModel):
    actor: PartyBriefOut
    waves: list[WaveOut] = Field(default_factory=list)


class MemberEvidenceOut(BaseModel):
    """The proof of a link. ``memberRunId`` is the other member that the link
    holds with. ``machineKey`` is the actor of an Actor link and the target of
    a Target as source link."""

    memberRunId: str | None = None
    machineKey: str | None = None
    machineName: str | None = None
    artifact: str | None = None
    communityId: str | None = None
    documentIds: list[str] = Field(default_factory=list)


class CampaignMemberOut(BaseModel):
    """One member investigation. ``verdict`` is null for an investigation that
    is no longer in the store. ``sourceKey`` and ``targetKey`` are the machine
    keys of the two ends, or null for an end that is no machine."""

    runId: str
    kind: str
    label: str
    verdict: str | None = None
    impact: str | None = None
    stage: str | None = None
    link: str
    evidence: MemberEvidenceOut
    direction: str
    eventAt: str | None = None
    finishedAt: str | None = None
    tier: str
    sourceAddress: str | None = None
    targetAddress: str | None = None
    verdictDiffers: bool = False
    huntId: str | None = None
    sourceKey: str | None = None
    targetKey: str | None = None
    # True when the authorization mark of the investigation holds, and when an
    # analyst joined it to the campaign.
    authorized: bool = False
    included: bool = False
    # A finding whose text names a known machine that is no host of the
    # finding: the note of soc_ai.campaigns.finding_names. Null for no note.
    nameNote: str | None = None


class RelatedRunOut(BaseModel):
    runId: str
    label: str
    finishedAt: str | None = None
    sourceAddress: str | None = None
    targetAddress: str | None = None


class RelatedSessionOut(BaseModel):
    source: PartyBriefOut
    target: PartyBriefOut
    port: int
    dataset: str | None = None
    documents: int
    firstAt: str
    lastAt: str
    documentIds: list[str] = Field(default_factory=list)


class NamedHostOut(BaseModel):
    value: str
    documents: int
    documentIds: list[str] = Field(default_factory=list)


class CampaignRelatedOut(BaseModel):
    """The candidates that no link proves. The engine adds none of them."""

    needsMoreInfo: list[RelatedRunOut] = Field(default_factory=list)
    sessions: list[RelatedSessionOut] = Field(default_factory=list)
    named: list[NamedHostOut] = Field(default_factory=list)
    falsePositiveFromTargets: int = 0


class DetectionOut(BaseModel):
    stage: str
    tier: str
    runId: str
    eventAt: str
    verdictAt: str
    seconds: int


class CampaignEdgeOut(BaseModel):
    """One arrow of the attack graph: the true positive investigations from
    one machine to another. ``runs`` counts them. ``alerts`` counts the alert
    events of the confirmed rules between the two machines, or is null when
    the events hold no pair of the two machines. ``stage`` is the highest
    stage that an investigation of the arrow proves. ``beyond`` marks an arrow
    from a target that an attack worked on. ``fromDocuments`` marks an arrow
    that no investigation has as its two ends: an alert document of a finding
    shows it."""

    source: str
    target: str
    runs: int
    alerts: int | None = None
    stage: str | None = None
    firstAt: str
    lastAt: str
    beyond: bool = False
    fromDocuments: bool = False


class CampaignGraphOut(BaseModel):
    """The attack graph. A campaign of an earlier release has no arrows."""

    edges: list[CampaignEdgeOut] = Field(default_factory=list)


class EventRuleOut(BaseModel):
    """The alert events of one rule between two machines. ``verdict`` is
    ``true_positive`` for a confirmed rule. Another rule takes the verdict of
    the standing investigations of that rule between the two machines:
    ``false_positive``, ``needs_more_info`` or ``not_judged``."""

    name: str
    alerts: int
    firstAt: str
    lastAt: str
    verdict: str


class EventDatasetOut(BaseModel):
    name: str
    records: int


class EventPairOut(BaseModel):
    """The events between two machines. ``alerts`` counts the alert events of
    the confirmed rules, and ``otherAlerts`` the alert events of every other
    rule. ``records`` counts every grid record between the two machines, and
    is null unless the source is the grid."""

    source: str
    target: str
    alerts: int
    otherAlerts: int
    records: int | None = None
    firstAt: str | None = None
    lastAt: str | None = None
    rules: list[EventRuleOut] = Field(default_factory=list)
    datasets: list[EventDatasetOut] = Field(default_factory=list)


class EventBucketOut(BaseModel):
    at: str
    alerts: int


class EventLaneOut(BaseModel):
    machineKey: str
    buckets: list[EventBucketOut] = Field(default_factory=list)


class EventTimelineOut(BaseModel):
    """The alert events of the confirmed rules in buckets of ``bucketSeconds``."""

    bucketSeconds: int
    lanes: list[EventLaneOut] = Field(default_factory=list)


class CampaignEventsOut(BaseModel):
    """The events of the campaign. ``source`` is ``grid`` for a grid read,
    ``stored`` for the events that the investigations hold, and ``none`` for a
    merged or withdrawn campaign. ``readAt`` is the time of the grid read."""

    source: str
    readAt: str | None = None
    alerts: int = 0
    rules: int = 0
    findings: int = 0
    records: int | None = None
    pairs: list[EventPairOut] = Field(default_factory=list)
    timeline: EventTimelineOut
    # True for a stored grid read that is older than the content of the
    # campaign: the grid did not answer since. The page states ``readAt``.
    behind: bool = False
    # The last alert event of a confirmed rule of a pair, else null.
    lastAlertAt: str | None = None
    # The alert events of the confirmed rules after the newest investigation
    # event, or after the boundary of a decision when it is later (G6): the
    # count, the count of the rules and the time of the last. 0 and null
    # when the stored read holds none or is older than the campaign.
    laterAlerts: int = 0
    laterRules: int = 0
    laterLastAt: str | None = None


class CampaignDecisionOut(BaseModel):
    """The decision of the analyst. ``type`` is ``closed``, ``authorized`` or
    ``case``. ``reason`` is the reason of a close: ``handled_outside``,
    ``accepted_risk`` or ``test_over``."""

    type: str
    reason: str | None = None
    note: str | None = None
    by: str | None = None
    at: str | None = None


class CampaignChangeOut(BaseModel):
    """One change of the campaign. ``type`` is ``formed``, ``stage``,
    ``party``, ``decided``, ``reopened``, ``acknowledged``, ``beyond``,
    ``excluded``, ``included``, ``case_intent``, ``case``, ``case_failed`` or
    ``case_comment``. ``detail`` holds its facts: ``stage`` ``{from, to}``,
    ``party`` ``{names}``, ``decided`` ``{decision, reason, by}`` or
    ``{decision, authorizationId, label, by}``, ``reopened`` ``{cause, by?,
    note?, was?}`` with the cause ``revoked`` for a revoke and ``was`` the
    decision that the reopen ended ``{decision, reason, note, by, decidedAt,
    basis, label?}`` (absent on a change of an earlier release), ``acknowledged`` ``{alerts,
    failed}``, ``beyond`` ``{runId, why}``, ``excluded`` and ``included``
    ``{runId, by}``, ``case_intent`` ``{intentId, by, title, alerts}``,
    ``case`` ``{caseId, alerts, by, intentId?, url, link, existing?}``,
    ``case_failed`` ``{reason, intentId, by, cleared?}`` and ``case_comment``
    ``{caseId, for, changeId}`` with ``for`` ``stage`` or ``party``."""

    id: int
    type: str
    at: str
    detail: dict[str, Any] = Field(default_factory=dict)


class CampaignCaseOut(BaseModel):
    """The one Security Onion case of the campaign.

    ``state`` is ``open`` while the campaign holds the decision ``case``.
    ``pending`` is a press whose answer soc-ai could not read: a case can
    exist, and "Try again" clears the press. ``failed`` is a press that
    opened no case, with ``failure``. ``id`` and ``url`` name the case, and
    are null before soc-ai knows it. ``openedAt`` and ``by`` are the time and
    the analyst of the press. ``alerts`` counts the alerts that the press
    attached, or plans to attach while ``pending``. ``comments`` counts the
    comments that soc-ai added to the case."""

    id: str | None = None
    url: str | None = None
    openedAt: str | None = None
    by: str | None = None
    alerts: int = 0
    comments: int = 0
    state: str
    failure: str | None = None


class CampaignRecordOut(BaseModel):
    """The authorization of the campaign. ``state`` is ``active``, ``expired``
    or ``revoked``. ``machineKeys`` are the listed machines. ``inside`` and
    ``outside`` count the true positive investigations that it covers or does
    not cover."""

    id: int
    label: str
    note: str | None = None
    by: str
    at: str
    startsAt: str
    expiresAt: str
    state: str
    machineKeys: list[str] = Field(default_factory=list)
    inside: int = 0
    outside: int = 0


class BeyondOut(BaseModel):
    """One true positive investigation beyond the authorization. ``why`` is
    ``source``, ``target``, ``expired`` or ``machine``."""

    runId: str
    label: str
    eventAt: str | None = None
    sourceKey: str | None = None
    targetKey: str | None = None
    why: str


class ExcludedOut(BaseModel):
    """One investigation that an analyst took out of the campaign."""

    runId: str
    label: str
    by: str
    at: str
    reason: str


class CampaignLeadOut(BaseModel):
    """One lead on the campaign page. ``state`` is the stored status of the
    lead: ``open``, ``hunting``, ``dismissed``, ``promoted`` or
    ``fleet_condition``. ``hunted`` is true when a hunt of any status names
    the lead. ``related`` is false for a lead of the campaign, and true for a
    lead that no campaign holds, whose entity is a machine of the campaign,
    with an observation in the period of the campaign."""

    id: int
    title: str
    state: str
    hunted: bool = False
    related: bool = False


class CampaignHuntOut(BaseModel):
    """One hunt for the campaign. ``starter`` is ``analyst``, ``schedule``,
    ``lead``, ``campaign`` or ``catalog``. ``findings`` counts the findings of
    the report, and ``threatFindings`` the threat findings among them.
    ``answer`` is the answer of a hunt that read the campaign:
    ``new_activity``, ``continues`` or ``no_new_event``, else null."""

    id: str
    starter: str
    status: str
    startedAt: str
    findings: int = 0
    threatFindings: int = 0
    answer: str | None = None
    # The steps of a hunt that stopped, so the fold reads "Stopped with an
    # error after 14 steps" as the hunt page does. Null for any other hunt.
    steps: int | None = None


class HuntAnswerOut(BaseModel):
    """What one hunt found for the campaign that it read (migration 0074).

    ``outcome`` is ``new_activity``: a threat finding names a machine of the
    campaign, ``continues``: a finding repeats the known activity of the
    campaign, or ``no_new_event``. ``findingTitle`` names the finding behind
    the first two. ``huntAt`` is the time that the hunt started."""

    huntId: str
    huntAt: str | None = None
    starter: str
    outcome: str
    findingOrdinal: int | None = None
    findingTitle: str | None = None


class CampaignOut(BaseModel):
    """One campaign. A merged or withdrawn campaign has empty sections.

    ``decision`` is null while the campaign waits on the analyst. ``state``
    is the one state that the console shows: the decision in force, else the
    status. ``waitsSince`` is the first event, or the time the campaign opened again,
    and null when it holds a decision. ``changes`` lists at most 50 changes,
    the newest first. ``leads`` lists the leads of the campaign and the
    related leads. ``hunts`` lists the hunts for the campaign.
    """

    id: int
    title: str
    status: str
    state: str = ""
    mergedInto: int | None = None
    earlierCampaign: EarlierCampaignOut | None = None
    bottomLine: str
    stage: str | None = None
    firstEvent: str
    lastEvent: str
    builtAt: str
    stale: bool = False
    authorizations: list[CampaignAuthorizationOut] = Field(default_factory=list)
    ladder: list[StageStepOut] = Field(default_factory=list)
    parties: list[CampaignPartyOut] = Field(default_factory=list)
    waves: list[ActorWavesOut] = Field(default_factory=list)
    members: list[CampaignMemberOut] = Field(default_factory=list)
    related: CampaignRelatedOut = Field(default_factory=CampaignRelatedOut)
    detection: list[DetectionOut] = Field(default_factory=list)
    graph: CampaignGraphOut = Field(default_factory=CampaignGraphOut)
    events: CampaignEventsOut
    decision: CampaignDecisionOut | None = None
    waitsSince: str | None = None
    changes: list[CampaignChangeOut] = Field(default_factory=list)
    authorization: CampaignRecordOut | None = None
    beyond: list[BeyondOut] = Field(default_factory=list)
    excluded: list[ExcludedOut] = Field(default_factory=list)
    # The leads of the campaign, then its related leads (``related`` true).
    leads: list[CampaignLeadOut] = Field(default_factory=list)
    # The hunts for the campaign, the newest first, at most 20.
    hunts: list[CampaignHuntOut] = Field(default_factory=list)
    # The one Security Onion case of the campaign, or null.
    case: CampaignCaseOut | None = None
    # What the hunts that read the campaign found, the newest hunt first, at
    # most 20.
    answers: list[HuntAnswerOut] = Field(default_factory=list)
    # What is new since the decision that a reopen ended, else null (SD2).
    sinceDecision: SinceDecisionOut | None = None
    # The later of ``lastEvent`` and ``events.lastAlertAt``: each surface
    # states the span of the campaign to it.
    lastActivity: str | None = None


def _iso(at: datetime | None) -> str | None:
    return _iso_utc(at) if at is not None else None


def _brief_out(brief: campaign_svc.PartyBrief) -> PartyBriefOut:
    return PartyBriefOut(machineKey=brief.machine_key, name=brief.name, address=brief.address)


def _row_out(row: campaign_svc.CampaignRow) -> CampaignRowOut:
    return CampaignRowOut(
        id=row.id,
        title=row.title,
        status=row.status,
        stage=row.stage,
        actors=[_brief_out(b) for b in row.actors],
        targets=[_brief_out(b) for b in row.targets],
        targetsMore=row.targets_more,
        firstEvent=_iso_utc(row.first_event),
        lastEvent=_iso_utc(row.last_event),
        members=row.members,
        alerts=row.alerts,
        decision=row.decision,
        state=row.state,
        waitsSince=_iso(row.waits_since),
        authorization=(
            RowAuthorizationOut(
                expiresAt=_iso_utc(row.authorization_expires_at),
                state=row.authorization_state,
            )
            if row.authorization_expires_at is not None and row.authorization_state is not None
            else None
        ),
        beyond=row.beyond,
        case=(
            CampaignRowCaseOut(openedAt=_iso_utc(row.case_opened_at))
            if row.decision == decisions.DECISION_CASE and row.case_opened_at is not None
            else None
        ),
        sinceDecision=since_out(row.since_decision),
        alertsReadAt=_iso(row.alerts_at),
        alertsBehind=row.alerts_behind,
        lastAlertAt=_iso(row.last_alert_at),
        lastActivity=_iso_utc(row.last_activity),
    )


def _decision_out(view: campaign_svc.CampaignView) -> CampaignDecisionOut | None:
    held = view.decision
    if held is None:
        return None
    return CampaignDecisionOut(
        type=held.type, reason=held.reason, note=held.note, by=held.by, at=_iso(held.at)
    )


def _member_out(member: campaign_svc.MemberView) -> CampaignMemberOut:
    evidence = member.evidence
    return CampaignMemberOut(
        runId=member.run_id,
        kind=member.kind,
        label=scrub_secrets(member.label),
        verdict=member.verdict,
        impact=member.impact,
        stage=member.stage,
        link=member.link,
        evidence=MemberEvidenceOut(
            memberRunId=evidence.member_run_id,
            machineKey=evidence.machine_key,
            machineName=evidence.machine_name,
            artifact=scrub_secrets(evidence.artifact) if evidence.artifact else None,
            communityId=evidence.community_id,
            documentIds=list(evidence.document_ids),
        ),
        direction=member.direction,
        eventAt=_iso(member.event_at),
        finishedAt=_iso(member.finished_at),
        tier=member.tier,
        sourceAddress=member.source_address,
        targetAddress=member.target_address,
        verdictDiffers=member.verdict_differs,
        huntId=member.hunt_id,
        sourceKey=member.source_key,
        targetKey=member.target_key,
        authorized=member.authorized,
        included=member.included,
    )


def _record_out(view: campaign_svc.CampaignView) -> CampaignRecordOut | None:
    held = view.authorization
    if held is None:
        return None
    return CampaignRecordOut(
        id=held.id,
        label=held.label,
        note=held.note,
        by=held.by,
        at=_iso_utc(held.at),
        startsAt=_iso_utc(held.starts_at),
        expiresAt=_iso_utc(held.expires_at),
        state=held.state,
        machineKeys=list(held.machine_keys),
        inside=held.inside,
        outside=held.outside,
    )


def _events_out(events: CampaignEvents, *, built_at: datetime | None = None) -> CampaignEventsOut:
    return CampaignEventsOut(
        behind=events.source == SOURCE_GRID
        and events.read_at is not None
        and built_at is not None
        and events.read_at < built_at,
        source=events.source,
        readAt=_iso(events.read_at),
        alerts=events.alerts,
        rules=events.rules,
        findings=events.findings,
        records=events.records,
        pairs=[
            EventPairOut(
                source=p.source,
                target=p.target,
                alerts=p.alerts,
                otherAlerts=p.other_alerts,
                records=p.records,
                firstAt=_iso(p.first_at),
                lastAt=_iso(p.last_at),
                rules=[
                    EventRuleOut(
                        name=scrub_secrets(r.name),
                        alerts=r.alerts,
                        firstAt=_iso_utc(r.first_at),
                        lastAt=_iso_utc(r.last_at),
                        verdict=r.verdict,
                    )
                    for r in p.rules
                ],
                datasets=[EventDatasetOut(name=d.name, records=d.records) for d in p.datasets],
            )
            for p in events.pairs
        ],
        timeline=EventTimelineOut(
            bucketSeconds=events.timeline.bucket_seconds,
            lanes=[
                EventLaneOut(
                    machineKey=lane.machine_key,
                    buckets=[
                        EventBucketOut(at=_iso_utc(b.at), alerts=b.alerts) for b in lane.buckets
                    ],
                )
                for lane in events.timeline.lanes
            ],
        ),
        lastAlertAt=_iso(events.last_alert_at),
        **_later_out(events.later),
    )


def _later_out(later: Any) -> dict[str, Any]:
    """The later alert events of a stored read in the API form, or none."""
    if later is None or not later.known or later.alerts <= 0:
        return {}
    return {
        "laterAlerts": later.alerts,
        "laterRules": later.rules,
        "laterLastAt": _iso(later.last_at),
    }


def _step_out(
    step: StageStep, headlines: dict[str, str], earlier: HeldBy | None = None
) -> StageStepOut:
    evidence = None
    if step.proof_document_id is not None and (step.proof_label or step.proof_at is not None):
        evidence = StageEvidenceOut(
            documentId=step.proof_document_id,
            label=scrub_secrets(step.proof_label),
            at=_iso(step.proof_at),
        )
    return StageStepOut(
        stage=step.stage,
        reached=step.reached,
        firstAt=_iso(step.first_at),
        members=step.members,
        proofRunId=step.proof_run_id,
        proofDocumentId=step.proof_document_id,
        headline=headlines.get(step.proof_run_id) if step.proof_run_id else None,
        evidence=evidence,
        heldBy=(
            StageHeldOut(at=_iso(earlier.at) or "", stage=earlier.stage)
            if earlier is not None
            else None
        ),
    )


def _edge_alerts(view: campaign_svc.CampaignView) -> dict[frozenset[str], int]:
    return {frozenset((p.source, p.target)): p.alerts for p in view.events.pairs}


async def _headlines(db: AsyncSession, run_ids: Sequence[str]) -> dict[str, str]:
    """What happened, in one sentence, for each proof investigation that the store holds."""
    # The threats route imports this module for the campaign rows.
    from soc_ai.api.webui.routes_threats import _what_happened  # noqa: PLC0415 - cycle

    wanted = sorted(set(run_ids))
    if not wanted:
        return {}
    rows = await db.scalars(select(Investigation).where(Investigation.id.in_(wanted)))
    out: dict[str, str] = {}
    for inv in rows.all():
        text = scrub_secrets(_what_happened(inv, {}, None)).strip()
        if text:
            out[str(inv.id)] = text
    return out


# The statuses of a hunt that the page names (routes_hunts._HUNT_STATUS).
_HUNT_STATUSES = ("running", "investigating", "complete", "error", "cancelled", "interrupted")


def _hunt_out(hunt: Any) -> CampaignHuntOut:
    """One hunt for the campaign. A catalog run reads ``catalog``, as on the Hunts page."""
    return CampaignHuntOut(
        id=str(hunt.id),
        starter="catalog" if hunt.kind == "triggered" else str(hunt.starter or "analyst"),
        status=hunt.status if hunt.status in _HUNT_STATUSES else "error",
        startedAt=_iso_utc(hunt.created_at),
        findings=int(hunt.findings_count or 0),
        threatFindings=int(hunt.threat_findings_count or 0),
    )


def _answer_out(view: hunt_answers.AnswerView) -> HuntAnswerOut:
    return HuntAnswerOut(
        huntId=view.hunt_id,
        huntAt=_iso(view.hunt_at),
        starter=view.starter,
        outcome=view.outcome,
        findingOrdinal=view.finding_ordinal,
        findingTitle=scrub_secrets(view.finding_title) if view.finding_title else None,
    )


def _campaign_out(
    view: campaign_svc.CampaignView,
    *,
    stale: bool,
    headlines: dict[str, str] | None = None,
    leads: Sequence[lead_tags.CampaignLead] = (),
    hunts: Sequence[Any] = (),
) -> CampaignOut:
    alerts = _edge_alerts(view)
    held = headlines or {}
    earlier = held_by({s.stage: s.first_at for s in view.ladder if s.reached})
    return CampaignOut(
        id=view.id,
        title=view.title,
        status=view.status,
        state=campaign_svc.api_state(
            view.status, view.decision.type if view.decision is not None else None
        ),
        mergedInto=view.merged_into,
        earlierCampaign=(
            EarlierCampaignOut(id=view.earlier.id, title=view.earlier.title)
            if view.earlier is not None
            else None
        ),
        bottomLine=view.bottom_line,
        stage=view.stage,
        firstEvent=_iso_utc(view.first_event),
        lastEvent=_iso_utc(view.last_event),
        builtAt=_iso_utc(view.built_at),
        stale=stale,
        authorizations=[
            CampaignAuthorizationOut(
                id=a.id,
                label=a.label,
                state=a.state,
                expiresAt=_iso_utc(a.expires_at),
                memberRuns=a.member_runs,
            )
            for a in view.authorizations
        ],
        ladder=[_step_out(s, held, earlier.get(s.stage)) for s in view.ladder],
        parties=[
            CampaignPartyOut(
                machineKey=p.machine_key,
                name=p.name,
                role=p.role,
                addresses=list(p.addresses),
                join=p.join,
                hasAgent=p.has_agent,
                firstEvent=_iso(p.first_event),
                lastEvent=_iso(p.last_event),
                memberRuns=p.member_runs,
                beyond=p.beyond,
            )
            for p in view.parties
        ],
        waves=[
            ActorWavesOut(
                actor=_brief_out(w.actor),
                waves=[
                    WaveOut(n=x.n, start=_iso_utc(x.start), end=_iso_utc(x.end), events=x.events)
                    for x in w.waves
                ],
            )
            for w in view.waves
        ],
        members=[_member_out(m) for m in view.members],
        related=CampaignRelatedOut(
            needsMoreInfo=[
                RelatedRunOut(
                    runId=r.run_id,
                    label=scrub_secrets(r.label),
                    finishedAt=_iso(r.finished_at),
                    sourceAddress=r.source_address,
                    targetAddress=r.target_address,
                )
                for r in view.needs_more_info
            ],
            sessions=[
                RelatedSessionOut(
                    source=_brief_out(s.source),
                    target=_brief_out(s.target),
                    port=s.port,
                    dataset=s.dataset,
                    documents=s.documents,
                    firstAt=_iso_utc(s.first_at),
                    lastAt=_iso_utc(s.last_at),
                    documentIds=list(s.document_ids),
                )
                for s in view.sessions
            ],
            named=[
                NamedHostOut(value=n.value, documents=n.documents, documentIds=list(n.document_ids))
                for n in view.named
            ],
            falsePositiveFromTargets=view.false_positive_from_targets,
        ),
        detection=[
            DetectionOut(
                stage=d.stage,
                tier=d.tier,
                runId=d.run_id,
                eventAt=_iso_utc(d.event_at),
                verdictAt=_iso_utc(d.verdict_at),
                seconds=d.seconds,
            )
            for d in view.detection
        ],
        graph=CampaignGraphOut(
            edges=[
                CampaignEdgeOut(
                    source=e.source,
                    target=e.target,
                    runs=e.runs,
                    alerts=alerts.get(frozenset((e.source, e.target))),
                    stage=e.stage,
                    firstAt=_iso_utc(e.first_at),
                    lastAt=_iso_utc(e.last_at),
                    beyond=e.beyond,
                    fromDocuments=e.from_documents,
                )
                for e in view.edges
            ]
        ),
        events=_events_out(view.events, built_at=view.built_at),
        decision=_decision_out(view),
        waitsSince=_iso(view.waits_since),
        changes=[
            CampaignChangeOut(
                id=c.id,
                type=c.type,
                at=_iso_utc(c.created_at),
                detail=c.detail if isinstance(c.detail, dict) else {},
            )
            for c in view.changes
        ],
        authorization=_record_out(view),
        beyond=[
            BeyondOut(
                runId=b.run_id,
                label=scrub_secrets(b.label),
                eventAt=_iso(b.event_at),
                sourceKey=b.source_key,
                targetKey=b.target_key,
                why=b.why,
            )
            for b in view.beyond
        ],
        excluded=[
            ExcludedOut(
                runId=e.run_id,
                label=scrub_secrets(e.label),
                by=e.by,
                at=_iso_utc(e.at),
                reason=scrub_secrets(e.reason),
            )
            for e in view.excluded
        ],
        leads=[
            CampaignLeadOut(
                id=lead.id,
                title=lead.title,
                state=lead.state,
                hunted=lead.hunted,
                related=lead.related,
            )
            for lead in leads
        ],
        hunts=[_hunt_out(h) for h in hunts],
        sinceDecision=since_out(view.since_decision),
        lastActivity=_iso_utc(view.last_activity),
    )


@router.get("/campaigns", response_model=CampaignsOut)
async def list_campaigns(request: Request) -> CampaignsOut:
    """The active campaigns, the newest last event first.

    ``status`` is ``open`` while the last activity is inside one horizon,
    else ``ended``. The last activity is the later of the last investigation
    event and the last alert event of a confirmed rule. ``stale`` is true
    when the rebuild failed.
    """
    async with request.app.state.db_sessionmaker() as db:
        fresh = await campaign_svc.ensure_fresh(db, audit=getattr(request.app.state, "audit", None))
        rows = await campaign_svc.list_campaigns(db)
    return CampaignsOut(rows=[_row_out(row) for row in rows], total=len(rows), stale=not fresh)


@router.get("/campaigns/{campaign_id}", response_model=CampaignOut)
async def get_campaign(
    request: Request,
    campaign_id: int,
    settings: Settings = Depends(get_settings_dep),
    elastic: ElasticClient = Depends(get_elastic),
) -> CampaignOut:
    """One campaign with its sections.

    An unknown id gives 404 with the reason ``campaign_not_found``. A merged
    or a withdrawn campaign gives its status, ``mergedInto``, empty sections
    and ``events.source`` ``none``. A failed grid read gives the events that
    the investigations hold, with ``events.source`` ``stored``.
    """
    async with request.app.state.db_sessionmaker() as db:
        fresh = await campaign_svc.ensure_fresh(db, audit=getattr(request.app.state, "audit", None))
        await campaign_svc.refresh_events(db, campaign_id, elastic, settings)
        return await _read_out(db, campaign_id, fresh=fresh)


async def _reopen_hunt(
    db: AsyncSession, since: since_svc.SinceDecision, hunts: Sequence[Any]
) -> SinceHuntOut | None:
    """The hunt that the reopen started, with the outcome words of the hunt page (W1).

    The campaign hunt loop starts one hunt for a reopen by new activity
    (:mod:`soc_ai.hunting.campaign_hunt`), within the horizon of a change
    after the reopen. The first such hunt of the campaign is the hunt of the
    reopen. A reopen by the analyst or by a revoke starts no hunt. Production,
    2026-11-18: that hunt confirmed 1 and found 1 false positive, and the
    campaign page named only the newest scheduled hunt, which found nothing.
    """
    if since.cause in (decisions.CAUSE_ANALYST, decisions.CAUSE_REVOKED):
        return None
    start = since.reopened_at
    end = start + campaign_hunt.CHANGE_HORIZON
    started = sorted(
        (
            h
            for h in hunts
            if str(h.starter or "") == campaign_hunt.STARTER
            and h.created_at is not None
            and start <= h.created_at <= end
        ),
        key=lambda h: (h.created_at, str(h.id)),
    )
    if not started:
        return None
    hunt = started[0]
    from soc_ai.api.webui.routes_hunts import (  # noqa: PLC0415 - routes_hunts reads this module
        _lead_hunt_state,
    )
    from soc_ai.store import hunts as hunt_svc  # noqa: PLC0415 - lazy

    verdicts = (await hunt_svc.finding_verdicts(db, [str(hunt.id)])).get(str(hunt.id))
    status, outcome = _lead_hunt_state(hunt, verdicts)
    return SinceHuntOut(
        id=str(hunt.id),
        startedAt=_iso_utc(hunt.created_at),
        status=status or "error",
        outcome=outcome,
    )


def _not_found() -> Exception:
    return api_error(404, "campaign_not_found", "No campaign has this id. Open the campaign list.")


async def _read_out(db: AsyncSession, campaign_id: int, *, fresh: bool) -> CampaignOut:
    """The API form of one campaign as the store holds it, or 404."""
    view = await campaign_svc.get_campaign(db, campaign_id)
    if view is None:
        raise _not_found()
    proofs = [s.proof_run_id for s in view.ladder if s.proof_run_id]
    hunt_rows = await lead_tags.hunts_of(db, campaign_id)
    out = _campaign_out(
        view,
        stale=not fresh,
        headlines=await _headlines(db, proofs),
        leads=await lead_tags.leads_of(db, campaign_id),
        hunts=hunt_rows,
    )
    if out.sinceDecision is not None and view.since_decision is not None:
        out.sinceDecision.reopenHunt = await _reopen_hunt(db, view.since_decision, hunt_rows)
    out.case = await _case_out(db, campaign_id)
    # A merged or a withdrawn campaign has empty sections.
    if view.status not in (campaign_svc.STATUS_MERGED, campaign_svc.STATUS_WITHDRAWN):
        family = await campaign_hunt.family(db, campaign_id)
        views = await hunt_answers.answers_of(db, hunt_answers.SUBJECT_CAMPAIGN, family)
        out.answers = [_answer_out(v) for v in views]
        outcomes = {a.huntId: a.outcome for a in out.answers}
        for hunt in out.hunts:
            hunt.answer = outcomes.get(hunt.id)
    # The steps of each hunt that stopped (routes_hunts.STOPPED_STATUSES).
    from soc_ai.api.webui.routes_hunts import (  # noqa: PLC0415 - routes_hunts reads this module
        STOPPED_STATUSES,
        _step_counts,
    )

    stopped = [h.id for h in out.hunts if h.status in STOPPED_STATUSES]
    steps = await _step_counts(db, stopped)
    for hunt in out.hunts:
        if hunt.id in stopped:
            hunt.steps = steps.get(hunt.id, 0)
    await _name_notes(db, out.members)
    return out


async def _name_notes(db: AsyncSession, members: list[CampaignMemberOut]) -> None:
    """Set the name note on each finding member whose finding has one."""
    ids = sorted({m.runId for m in members if m.kind == KIND_FINDING})
    runs: list[Investigation] = []
    for part in chunked(ids):
        runs.extend(
            (await db.scalars(select(Investigation).where(Investigation.id.in_(part)))).all()
        )
    notes = await finding_names.notes_for_runs(db, runs)
    for m in members:
        m.nameNote = notes.get(m.runId)


def _detail_of(change: Any) -> dict[str, Any]:
    return dict(change.detail) if isinstance(change.detail, dict) else {}


async def _case_out(db: AsyncSession, campaign_id: int) -> CampaignCaseOut | None:
    """The case of a campaign: open, pending or failed, else None.

    A press with no result is ``pending`` whatever the decision. The case is
    ``open`` while the campaign holds the decision ``case``. A failed press
    shows while the campaign holds no decision. After "Open again" the case
    stays in Security Onion and ``GET /case-scope`` names it, and this field
    is null until the next press records the decision again.
    """
    row = await db.get(Campaign, campaign_id)
    if row is None:
        return None
    state = await campaign_case.state_of(db, row)
    if state.open_intent is not None:
        held = _detail_of(state.open_intent)
        alerts = held.get("alerts")
        return CampaignCaseOut(
            state=campaign_case.STATE_PENDING,
            openedAt=_iso_utc(state.open_intent.created_at),
            by=str(held.get("by") or "") or None,
            alerts=alerts if isinstance(alerts, int) else 0,
        )
    if row.decision == decisions.DECISION_CASE:
        record = state.record
        if record is None:
            return CampaignCaseOut(
                id=row.case_id,
                state=campaign_case.STATE_OPEN,
                openedAt=_iso(row.decided_at),
                by=row.decided_by,
            )
        return CampaignCaseOut(
            id=record.case_id,
            url=record.url,
            openedAt=_iso_utc(record.opened_at),
            by=record.by or None,
            alerts=record.alerts,
            comments=state.comments,
            state=campaign_case.STATE_OPEN,
        )
    if row.decision is None and state.failed is not None:
        held = _detail_of(state.failed)
        return CampaignCaseOut(
            state=campaign_case.STATE_FAILED,
            openedAt=_iso_utc(state.failed.created_at),
            by=str(held.get("by") or "") or None,
            failure=campaign_case.failure_of(state.failed),
        )
    return None


class CloseScopeOut(BaseModel):
    """The alert events that a close acknowledges. ``alerts`` and ``rules``
    are null when soc-ai could not read the grid. ``capped`` is true when more
    than 2,000 alert events wait, and the close acknowledges 2,000."""

    alerts: int | None = None
    rules: int | None = None
    capped: bool = False


class CloseIn(BaseModel):
    """A close of a campaign. ``acknowledge`` acknowledges the alerts of the
    close scope in Security Onion after the close."""

    reason: Literal["handled_outside", "accepted_risk", "test_over"]
    note: str = Field(default="", max_length=2000)
    acknowledge: bool = False


class ReopenIn(BaseModel):
    note: str = Field(default="", max_length=2000)


def _note(text: str) -> str:
    return scrub_secrets(text.strip())


@router.get("/campaigns/{campaign_id}/close-scope", response_model=CloseScopeOut)
async def campaign_close_scope(
    request: Request,
    campaign_id: int,
    settings: Settings = Depends(get_settings_dep),
    elastic: ElasticClient = Depends(get_elastic),
) -> CloseScopeOut:
    """The alert events that a close of the campaign acknowledges.

    The events of the confirmed rules between the machines of the campaign,
    in its period, that Security Onion has not acknowledged. At most 2,000.
    The period of an open campaign ends at the end of the grid read that the
    page states, and the close records that time in its basis. A failed grid
    read gives ``alerts`` null, never 0. An unknown id gives 404.
    """
    async with request.app.state.db_sessionmaker() as db:
        scope = await campaign_svc.close_scope(db, campaign_id, elastic, settings)
    if scope is None:
        raise _not_found()
    return CloseScopeOut(alerts=scope.alerts, rules=scope.rules, capped=scope.capped)


async def _acknowledge_ids(
    request: Request, campaign_id: int, alert_ids: Sequence[str], by: str
) -> dict[str, Any]:
    """Acknowledge *alert_ids* through the acknowledge path of the Alerts page.

    ``_ack_many`` gives each write its own audit records. The detail of the
    ``acknowledged`` change: the count acknowledged and the count that failed.
    """
    from soc_ai.api.webui.routes_alert_actions import _ack_many  # noqa: PLC0415 - cycle

    acked, failed = (
        await _ack_many(
            request, list(alert_ids), session_id=f"campaign-close:{campaign_id}", caller=by
        )
        if alert_ids
        else (0, 0)
    )
    return {"alerts": acked, "failed": failed}


async def _acknowledge_after_close(
    request: Request,
    campaign_id: int,
    elastic: ElasticClient,
    settings: Settings,
    by: str,
) -> None:
    """Acknowledge the alerts of the close scope, then record one ``acknowledged`` change.

    It runs after the close is committed, through the acknowledge path of the
    Alerts page (``_ack_many``): each write has its own audit records. A
    failure here never undoes the close. A failed scope read records the
    change with ``unread`` true and no write. A restart while it runs loses
    the rest: ``POST /campaigns/{id}/acknowledge`` does the work again.
    """
    maker = request.app.state.db_sessionmaker
    try:
        async with maker() as db:
            scope = await campaign_svc.close_scope(db, campaign_id, elastic, settings)
        detail: dict[str, Any]
        if scope is None or scope.alerts is None:
            detail = {"alerts": 0, "failed": 0, "unread": True}
        else:
            detail = await _acknowledge_ids(request, campaign_id, scope.alert_ids, by)
        async with maker() as db:
            db.add(decisions.change(campaign_id, decisions.CHANGE_ACKNOWLEDGED, detail, utcnow()))
            await db.commit()
    except Exception:
        _LOGGER.warning(
            "campaigns: the acknowledge after the close of campaign %s failed. "
            "The campaign stays closed.",
            campaign_id,
            exc_info=True,
        )


async def _close_campaign_leads(db: AsyncSession, campaign_id: int, reason: str) -> None:
    """D6: the leads of the campaign close with it. A failure keeps the decision.

    The step after a rebuild runs first. An investigation beyond an
    authorization then leaves its lead to normal handling, and that lead
    stays open. A lead that soc-ai could not close stays a lead of the
    campaign: it raises no Needs you item, and the next step closes it.
    """
    try:
        now = utcnow()
        await lead_tags.after_rebuild(db, now=now)
        await lead_tags.close_leads(db, campaign_id, reason=reason, now=now)
    except Exception:
        _LOGGER.warning(
            "campaigns: soc-ai could not close the leads of campaign %s. The next step "
            "after a rebuild closes them.",
            campaign_id,
            exc_info=True,
        )
        with contextlib.suppress(Exception):
            await db.rollback()


@router.post("/campaigns/{campaign_id}/close", response_model=CampaignOut)
async def close_campaign(
    request: Request,
    campaign_id: int,
    body: CloseIn,
    background: BackgroundTasks,
    settings: Settings = Depends(get_settings_dep),
    elastic: ElasticClient = Depends(get_elastic),
) -> CampaignOut:
    """Close a campaign with a reason. A signed-in analyst may close.

    The close covers only the past: new activity opens the campaign again. It
    changes no verdict. The order: the audit record ``campaign_closed``, then
    the decision and one ``decided`` change, then the commit. When the audit
    write fails, nothing changes and the route answers 503. When the store
    write fails after the record, the route writes ``campaign_close_failed``
    and answers 503 ``store_unavailable``. With ``acknowledge``, a task
    acknowledges the alerts of the close scope after the commit and records
    one ``acknowledged`` change.

    Refusals: 404 ``campaign_not_found``; 409 ``campaign_not_active`` and
    ``campaign_decided``; 503 ``audit_unavailable`` and ``store_unavailable``.
    """
    by = await identify_caller(request)
    audit = getattr(request.app.state, "audit", None)
    note = _note(body.note)
    async with request.app.state.db_sessionmaker() as db:
        fresh = await campaign_svc.ensure_fresh(db, audit=getattr(request.app.state, "audit", None))
        row = await db.get(Campaign, campaign_id, populate_existing=True)
        if row is None:
            raise _not_found()
        _refuse_closed(row)
        # The close covers what the page states: the later alert events of
        # the grid read too (G3).
        basis = await campaign_svc.close_basis(db, row)
        title = row.title
        # End the read snapshot: the write below reads the row again.
        await db.rollback()
        # The audit record first. A close hides work, so it never stands
        # without its record.
        closed = {
            "campaign_id": campaign_id,
            "title": title,
            "reason": body.reason,
            "note": note,
            "acknowledge": body.acknowledge,
            "basis": basis,
        }
        try:
            if audit is not None:
                await audit.log_kind(
                    AUDIT_SESSION, "campaign_closed", closed, user=by, mutating=True
                )
        except Exception as exc:
            _LOGGER.warning("campaigns: the close record failed, nothing saved: %s", exc)
            raise api_error(
                503,
                "audit_unavailable",
                "soc-ai could not write the audit record, so it did not close the campaign. "
                "Try again when the grid answers.",
            ) from exc
        # The record is on the trail now. A close that then fails to land
        # gets a second record that states it did not happen.
        try:
            row = await decisions.write_close(
                db,
                campaign_id,
                reason=body.reason,
                note=note,
                by=by,
                basis=basis,
                now=utcnow(),
                acknowledge=body.acknowledge,
            )
        except Exception as exc:
            raise await fail_after_record(
                request, db, exc, AUDIT_SESSION, "campaign_closed", closed, by=by, action="close"
            ) from exc
        if row is None:
            await db.rollback()
            await record_failed(
                request, AUDIT_SESSION, "campaign_closed", closed, by=by, cause="campaign_decided"
            )
            raise api_error(
                409, "campaign_decided", "An analyst decided on this campaign a moment ago."
            )
        await commit_after_record(
            request, db, AUDIT_SESSION, "campaign_closed", closed, by=by, action="close"
        )
        await _close_campaign_leads(db, campaign_id, leads_store.CAMPAIGN_CLOSED_REASON)
        out = await _read_out(db, campaign_id, fresh=fresh)
    if body.acknowledge:
        background.add_task(_acknowledge_after_close, request, campaign_id, elastic, settings, by)
    return out


@router.post("/campaigns/{campaign_id}/acknowledge", response_model=CampaignOut)
async def acknowledge_campaign(
    request: Request,
    campaign_id: int,
    settings: Settings = Depends(get_settings_dep),
    elastic: ElasticClient = Depends(get_elastic),
) -> CampaignOut:
    """Acknowledge the alerts of a closed campaign that are still open. A signed-in analyst may.

    The acknowledgement of a close runs as a task after the commit, and a
    restart in that minute loses the rest. This route reads the close scope
    again, acknowledges what Security Onion still holds as open through the
    acknowledge path of the Alerts page, and records one ``acknowledged``
    change. A failed write counts in ``failed`` and never undoes the close.

    Refusals: 404 ``campaign_not_found``; 409 ``campaign_not_closed``; 503
    ``grid_unavailable``.
    """
    by = await identify_caller(request)
    async with request.app.state.db_sessionmaker() as db:
        fresh = await campaign_svc.ensure_fresh(db, audit=getattr(request.app.state, "audit", None))
        row = await db.get(Campaign, campaign_id, populate_existing=True)
        if row is None:
            raise _not_found()
        if row.status != campaign_svc.STATUS_ACTIVE or row.decision != decisions.DECISION_CLOSED:
            raise api_error(
                409,
                "campaign_not_closed",
                "This campaign is not closed. Close it with a reason to acknowledge its alerts.",
            )
        scope = await campaign_svc.close_scope(db, campaign_id, elastic, settings)
    if scope is None:
        raise _not_found()
    if scope.alerts is None:
        raise api_error(
            503,
            "grid_unavailable",
            "soc-ai could not read the alerts of the campaign from the grid. Try again.",
        )
    detail = await _acknowledge_ids(request, campaign_id, scope.alert_ids, by)
    async with request.app.state.db_sessionmaker() as db:
        db.add(decisions.change(campaign_id, decisions.CHANGE_ACKNOWLEDGED, detail, utcnow()))
        await db.commit()
        return await _read_out(db, campaign_id, fresh=fresh)


def _refuse_closed(row: Campaign) -> None:
    if row.status != campaign_svc.STATUS_ACTIVE:
        raise api_error(
            409,
            "campaign_not_active",
            f"This campaign is {row.status}. Decide on the campaign that holds its activity.",
        )
    if row.decision is not None:
        raise api_error(
            409,
            "campaign_decided",
            "This campaign holds a decision. Open it again before a new decision.",
        )


@router.post("/campaigns/{campaign_id}/reopen", response_model=CampaignOut)
async def reopen_campaign(request: Request, campaign_id: int, body: ReopenIn) -> CampaignOut:
    """Open a decided campaign again. A signed-in analyst may open it.

    The decision is cleared, one ``reopened`` change states the analyst, and
    the campaign waits in Needs you again. The audit record
    ``campaign_reopened`` follows the commit.

    Refusals: 404 ``campaign_not_found``; 409 ``campaign_not_decided``; 503
    ``store_unavailable``.
    """
    by = await identify_caller(request)
    note = _note(body.note)
    async with request.app.state.db_sessionmaker() as db:
        fresh = await campaign_svc.ensure_fresh(db, audit=getattr(request.app.state, "audit", None))
        row = await db.get(Campaign, campaign_id, populate_existing=True)
        if row is None:
            raise _not_found()
        if row.decision is None:
            raise api_error(
                409, "campaign_not_decided", "This campaign holds no decision to open again."
            )
        if row.decision == decisions.DECISION_AUTHORIZED:
            # An open again would leave the marks of the record in force.
            raise api_error(
                409,
                "campaign_authorized",
                "This campaign holds an authorization. Revoke the authorization to open it again.",
            )
        held = {"decision": row.decision, "reason": row.close_reason}
        decisions.write_reopen(db, row, by=by, note=note, now=utcnow())
        try:
            await db.commit()
        except Exception as exc:
            # The record follows the commit, so the trail holds nothing to undo.
            await db.rollback()
            _LOGGER.warning("campaigns: the reopen of campaign %s failed: %s", campaign_id, exc)
            raise store_unavailable("reopen") from exc
        await _audit(
            request,
            "campaign_reopened",
            {"campaign_id": campaign_id, "title": row.title, "note": note, **held},
            by,
        )
        return await _read_out(db, campaign_id, fresh=fresh)


# ── The authorization of a campaign ────────────────────────────────────────


class DraftPartyOut(BaseModel):
    """One machine of the campaign as the dialog lists it. ``address`` is its
    first address. ``listed`` is true by default: the admin can unlist it."""

    machineKey: str
    role: str
    name: str | None = None
    address: str | None = None
    listed: bool = True


class EarlierRecordOut(BaseModel):
    """A record of the rule-list form that covers part of the campaign:
    ``covers`` of the ``of`` true positive investigations."""

    id: int
    label: str
    covers: int
    of: int


class AuthorizeDraftOut(BaseModel):
    """What an authorization of the campaign covers before the press.

    ``inside`` and ``outside`` count the true positive investigations of the
    campaign that the scope with all parties covers or does not cover.
    ``waiting`` counts the inside investigations with a waiting action
    today. ``label`` and ``expiresAt`` are the defaults: the ones of an
    earlier record, else an empty label and seven days."""

    label: str = ""
    expiresAt: str
    maxExpiresAt: str
    startsAt: str
    parties: list[DraftPartyOut] = Field(default_factory=list)
    inside: int = 0
    outside: int = 0
    waiting: int = 0
    earlier: EarlierRecordOut | None = None


class AuthorizeIn(BaseModel):
    """An authorization of a campaign. ``machineKeys`` are the listed
    machines, each a party of the campaign. ``expiresAt`` is ISO UTC, later
    than now and at most 30 days away."""

    label: str = Field(default="", max_length=200)
    note: str = Field(default="", max_length=2000)
    expiresAt: str = Field(max_length=64)
    machineKeys: list[str] = Field(default_factory=list, max_length=200)


class RevokeAuthorizationIn(BaseModel):
    reason: str = Field(default="", max_length=512)


def _party_entries(parties: Sequence[Any]) -> list[authorized_svc.PartyEntry]:
    return [
        authorized_svc.PartyEntry(
            machine_key=str(p.machine_key),
            role=str(p.role),
            name=p.name,
            addresses=tuple(str(a) for a in (p.addresses if isinstance(p.addresses, list) else [])),
        )
        for p in parties
        if p.role in (authorized_svc.ROLE_ACTOR, authorized_svc.ROLE_TARGET)
    ]


def _draft_scope(
    row: Campaign, parties: Sequence[authorized_svc.PartyEntry], expires_at: datetime
) -> authorized_svc.Scope:
    """The scope that a record with these parties would have, for the counts."""
    return authorized_svc.Scope(
        id=0,
        label="",
        sources=(),
        target=authorized_svc.ScopeEntry(""),
        rule_names=(),
        rule_class="",
        starts_at=row.first_event,
        expires_at=expires_at,
        campaign_id=row.id,
        parties=tuple(parties),
    )


async def _earlier_record(
    db: AsyncSession, invs: Sequence[Investigation]
) -> EarlierRecordOut | None:
    """The record of the rule-list form that covers most of the investigations, or None."""
    counts: dict[int, int] = {}
    for inv in invs:
        if inv.authorization_id is not None:
            counts[int(inv.authorization_id)] = counts.get(int(inv.authorization_id), 0) + 1
    best: EarlierRecordOut | None = None
    for authorization_id, covers in sorted(counts.items(), key=lambda p: (-p[1], p[0])):
        row = await authorized_svc.get(db, authorization_id)
        if row is None or row.campaign_id is not None or row.revoked_at is not None:
            continue
        best = EarlierRecordOut(id=row.id, label=row.label, covers=covers, of=len(invs))
        break
    return best


def _parse_expiry(text: str) -> datetime:
    try:
        value = datetime.fromisoformat(text.strip().replace("Z", "+00:00"))
    except ValueError as exc:
        raise api_error(
            422, "bad_expiry", "The expiry is not a time. Send an ISO time in UTC."
        ) from exc
    return value.astimezone(UTC).replace(tzinfo=None) if value.tzinfo is not None else value


@router.get(
    "/campaigns/{campaign_id}/authorize-draft",
    response_model=AuthorizeDraftOut,
    dependencies=[Depends(require_admin_api)],
)
async def campaign_authorize_draft(request: Request, campaign_id: int) -> AuthorizeDraftOut:
    """What an authorization of the campaign covers, before the press. Admin only.

    Each party is listed by default. The counts read the scope with every
    party listed and the default expiry. A record of the rule-list form that
    covers part of the campaign gives the default label and expiry.

    Refusals: 404 ``campaign_not_found``; 409 ``campaign_not_active`` and
    ``campaign_decided``.
    """
    from soc_ai.api.webui.routes_meta import pending_actions_by_run  # noqa: PLC0415 - cycle

    now = utcnow()
    async with request.app.state.db_sessionmaker() as db:
        await campaign_svc.ensure_fresh(db, audit=getattr(request.app.state, "audit", None))
        row = await db.get(Campaign, campaign_id, populate_existing=True)
        if row is None:
            raise _not_found()
        _refuse_closed(row)
        party_rows = (await campaign_svc._parties_of(db, [row.id])).get(row.id, [])
        entries = _party_entries(party_rows)
        invs = await campaign_auth.true_positive_members(db, row.id)
        earlier = await _earlier_record(db, invs)
        expires = now + timedelta(days=authorized_svc.DEFAULT_DAYS)
        label = ""
        if earlier is not None:
            held = await authorized_svc.get(db, earlier.id)
            label = earlier.label
            if held is not None and now < held.expires_at <= now + timedelta(
                days=authorized_svc.MAX_DAYS
            ):
                expires = held.expires_at
        found = await campaign_auth.answers(db, _draft_scope(row, entries, expires), invs)
        inside = [inv for inv in invs if found.get(inv.id, campaign_auth.WHY_SOURCE) is None]
        waits = await pending_actions_by_run(db, inside, state=request.app.state, held=False)
        return AuthorizeDraftOut(
            label=label,
            expiresAt=_iso_utc(expires),
            maxExpiresAt=_iso_utc(now + timedelta(days=authorized_svc.MAX_DAYS)),
            startsAt=_iso_utc(row.first_event),
            parties=[
                DraftPartyOut(
                    machineKey=p.machine_key,
                    role=p.role,
                    name=p.name,
                    address=p.addresses[0] if p.addresses else None,
                )
                for p in entries
            ],
            inside=len(inside),
            outside=len(invs) - len(inside),
            waiting=sum(1 for inv in inside if waits.get(inv.id, 0) > 0),
            earlier=earlier,
        )


@router.post(
    "/campaigns/{campaign_id}/authorize",
    response_model=CampaignOut,
    dependencies=[Depends(require_admin_api)],
)
async def authorize_campaign(request: Request, campaign_id: int, body: AuthorizeIn) -> CampaignOut:
    """Record the activity of the campaign as authorized. Admin only.

    The record lists the machines of ``machineKeys``, each with its role in
    the campaign, and no rule. Its period starts at the first event of the
    campaign and ends at ``expiresAt``. The order: the record and the
    decision are flushed, the audit record ``authorized_activity_created`` is
    written, then the commit. When the audit write fails, nothing changes and
    the answer is 503. Each inside investigation then gets the mark, and each
    outside investigation gets one ``beyond`` change.

    Refusals: 404 ``campaign_not_found``; 409 ``campaign_not_active`` and
    ``campaign_decided``; 422 ``bad_expiry``, ``expiry_in_past``,
    ``expiry_too_far``, ``label_required``, ``machine_not_party``,
    ``actor_required`` and ``target_required``; 503 ``audit_unavailable``.
    """
    by = await identify_caller(request)
    audit = getattr(request.app.state, "audit", None)
    now = utcnow()
    expires = _parse_expiry(body.expiresAt)
    note = _note(body.note)
    async with request.app.state.db_sessionmaker() as db:
        fresh = await campaign_svc.ensure_fresh(db, audit=audit)
        row = await db.get(Campaign, campaign_id, populate_existing=True)
        if row is None:
            raise _not_found()
        _refuse_closed(row)
        by_key = {
            p.machine_key: p
            for p in _party_entries((await campaign_svc._parties_of(db, [row.id])).get(row.id, []))
        }
        wanted = list(dict.fromkeys(k.strip() for k in body.machineKeys if k.strip()))
        stranger = [k for k in wanted if k not in by_key]
        if stranger:
            raise api_error(
                422,
                "machine_not_party",
                f"{stranger[0]} is not a machine of this campaign. List only its parties.",
            )
        basis = await decisions.basis_for(db, row)
        try:
            record = await authorized_svc.create_for_campaign(
                db,
                campaign_id=row.id,
                label=body.label,
                note=note,
                parties=[by_key[k] for k in wanted],
                starts_at=row.first_event,
                expires_at=expires,
                created_by=by,
                now=now,
                commit=False,
            )
        except authorized_svc.ScopeError as exc:
            await db.rollback()
            raise api_error(422, exc.reason, exc.hint) from exc
        scope = authorized_svc.scope_of(record)
        decisions.write_authorize(
            db, row, authorization_id=record.id, label=scope.label, by=by, basis=basis, now=now
        )
        invs = await campaign_auth.true_positive_members(db, row.id)
        beyond = await campaign_auth.beyond_of(db, scope, invs)
        await campaign_auth.write_beyond(db, row.id, beyond, now=now)
        # The audit record first, then the commit. A record that hides work
        # always has its create record on the trail.
        created = {
            "authorization_id": record.id,
            "campaign_id": row.id,
            "label": scope.label,
            "parties": [p.as_json() for p in scope.parties],
            "starts_at": _iso_utc(scope.starts_at),
            "expires_at": _iso_utc(scope.expires_at),
            "inside": len(invs) - len(beyond),
            "outside": len(beyond),
        }
        try:
            if audit is not None:
                await audit.log_kind(
                    authorized_decision.AUDIT_SESSION,
                    "authorized_activity_created",
                    created,
                    user=by,
                    mutating=True,
                )
        except Exception as exc:
            await db.rollback()
            _LOGGER.warning("campaigns: the authorization record failed, nothing saved: %s", exc)
            raise api_error(
                503,
                "audit_unavailable",
                "soc-ai could not write the audit record, so it saved no authorization. "
                "Try again when the grid answers.",
            ) from exc
        await commit_after_record(
            request,
            db,
            authorized_decision.AUDIT_SESSION,
            "authorized_activity_created",
            created,
            by=by,
            action="authorization",
        )
        await campaign_auth.mark_inside(db, audit, scope, invs, now=now)
        await _close_campaign_leads(db, campaign_id, leads_store.CAMPAIGN_AUTHORIZED_REASON)
        return await _read_out(db, campaign_id, fresh=fresh)


@router.post("/campaigns/{campaign_id}/revoke-authorization", response_model=CampaignOut)
async def revoke_campaign_authorization(
    request: Request, campaign_id: int, body: RevokeAuthorizationIn
) -> CampaignOut:
    """Revoke the authorization of a campaign. A signed-in analyst may revoke.

    The reason is required. The revoke ends every mark of the record, clears
    the decision and writes one ``reopened`` change with the cause
    ``revoked``. The campaign then holds its investigations again and waits
    as one item. No investigation goes to the lead path. The audit record is
    written before the commit, and a failed write changes nothing.

    Refusals: 404 ``campaign_not_found``; 409 ``no_authorization``; 422
    ``reason_required``; 503 ``audit_unavailable``.
    """
    from soc_ai.api.webui.routes_authorized_activity import (  # noqa: PLC0415 - cycle
        revoke_campaign_record,
    )

    reason = " ".join(body.reason.split())
    if not reason:
        raise api_error(422, "reason_required", "State the reason for the revoke.")
    by = await identify_caller(request)
    now = utcnow()
    async with request.app.state.db_sessionmaker() as db:
        fresh = await campaign_svc.ensure_fresh(db, audit=getattr(request.app.state, "audit", None))
        row = await db.get(Campaign, campaign_id, populate_existing=True)
        if row is None:
            raise _not_found()
        record = (
            await authorized_svc.get(db, row.authorization_id) if row.authorization_id else None
        )
        if (
            row.decision != decisions.DECISION_AUTHORIZED
            or record is None
            or record.revoked_at is not None
        ):
            raise api_error(
                409, "no_authorization", "This campaign holds no authorization to revoke."
            )
        await revoke_campaign_record(request, db, record.id, reason=reason, by=by, now=now)
        return await _read_out(db, campaign_id, fresh=fresh)


# ── Exclude and include ────────────────────────────────────────────────────


class OverrideIn(BaseModel):
    """An exclusion or an inclusion of one investigation, with the reason of the analyst."""

    runId: str = Field(min_length=1, max_length=32)
    reason: str = Field(default="", max_length=2000)


def _reason(text: str) -> str:
    reason = _note(" ".join(text.split()))
    if not reason:
        raise api_error(422, "reason_required", "State the reason.")
    return reason


async def _write_override(
    request: Request,
    db: AsyncSession,
    kind: str,
    payload: dict[str, Any],
    by: str,
    *,
    action: str,
) -> None:
    """The audit record of an override before the commit, then the commit. Fails closed.

    A failed commit after the record writes the ``*_failed`` record of *kind*
    and answers 503 ``store_unavailable``.
    """
    audit = getattr(request.app.state, "audit", None)
    try:
        if audit is not None:
            await audit.log_kind(AUDIT_SESSION, kind, payload, user=by, mutating=True)
    except Exception as exc:
        await db.rollback()
        _LOGGER.warning("campaigns: the %s record failed, nothing changed: %s", kind, exc)
        raise api_error(
            503,
            "audit_unavailable",
            "soc-ai could not write the audit record, so it changed nothing. "
            "Try again when the grid answers.",
        ) from exc
    await commit_after_record(request, db, AUDIT_SESSION, kind, payload, by=by, action=action)


async def _refuse_overridden(db: AsyncSession, run_id: str) -> None:
    held = await db.scalar(
        select(CampaignRunOverride.type).where(CampaignRunOverride.run_id == run_id)
    )
    if held is not None:
        raise api_error(
            409,
            "already_overridden",
            f"An analyst {held} this investigation before. Undo that first.",
        )


async def _fresh_out(request: Request, db: AsyncSession, campaign_id: int) -> CampaignOut:
    fresh = await campaign_svc.ensure_fresh(db, audit=getattr(request.app.state, "audit", None))
    return await _read_out(db, campaign_id, fresh=fresh)


@router.post("/campaigns/{campaign_id}/exclude", response_model=CampaignOut)
async def exclude_from_campaign(
    request: Request, campaign_id: int, body: OverrideIn
) -> CampaignOut:
    """Take one investigation out of the campaign. A signed-in analyst may do it.

    The investigation joins no campaign and gets normal handling again. The
    mark of a campaign record on it ends. It forms no lead. One
    ``excluded`` change and the audit record ``campaign_excluded``, which is
    written before the commit: a failed write changes nothing.

    Refusals: 404 ``campaign_not_found`` and ``not_in_campaign``; 409
    ``already_overridden``; 422 ``reason_required``; 503 ``audit_unavailable``.
    """
    by = await identify_caller(request)
    reason = _reason(body.reason)
    run_id = body.runId.strip()
    now = utcnow()
    async with request.app.state.db_sessionmaker() as db:
        await campaign_svc.ensure_fresh(db, audit=getattr(request.app.state, "audit", None))
        row = await db.get(Campaign, campaign_id, populate_existing=True)
        if row is None:
            raise _not_found()
        # An exclusion takes the investigation out, so the override answers first.
        await _refuse_overridden(db, run_id)
        member = await db.scalar(
            select(CampaignMember.id).where(
                CampaignMember.campaign_id == campaign_id, CampaignMember.run_id == run_id
            )
        )
        if member is None:
            raise api_error(404, "not_in_campaign", "This investigation is not in this campaign.")
        db.add(
            CampaignRunOverride(
                run_id=run_id,
                type=campaign_svc.OVERRIDE_EXCLUDED,
                campaign_id=campaign_id,
                by=by,
                reason=reason,
                created_at=now,
            )
        )
        cleared = await _clear_campaign_mark(db, run_id)
        db.add(
            decisions.change(
                campaign_id, decisions.CHANGE_EXCLUDED, {"runId": run_id, "by": by}, now
            )
        )
        await _write_override(
            request,
            db,
            "campaign_excluded",
            {
                "campaign_id": campaign_id,
                "investigation_id": run_id,
                "reason": reason,
                "authorization_cleared": cleared,
            },
            by,
            action="exclusion",
        )
        return await _fresh_out(request, db, campaign_id)


async def _clear_campaign_mark(db: AsyncSession, run_id: str) -> int | None:
    """End the mark of a campaign record on one investigation. The id of that record, or None.

    A mark of a record of the rule-list form stays: that record is no part
    of the campaign.
    """
    inv = await db.get(Investigation, run_id)
    if inv is None or inv.authorization_id is None:
        return None
    record = await authorized_svc.get(db, inv.authorization_id)
    if record is None or record.campaign_id is None:
        return None
    report = dict(inv.report) if isinstance(inv.report, dict) else {}
    held = report.get(authorized_svc.REPORT_KEY)
    if isinstance(held, dict) and held.get("id") == record.id:
        report.pop(authorized_svc.REPORT_KEY)
        inv.report = report
    inv.authorization_id = None
    return int(record.id)


@router.post("/campaigns/{campaign_id}/include", response_model=CampaignOut)
async def include_in_campaign(request: Request, campaign_id: int, body: OverrideIn) -> CampaignOut:
    """Join one investigation of "Related, not proven" to the campaign. A signed-in analyst may.

    The anchor is the seed of the campaign now: the investigation joins the
    campaign that holds the seed at each rebuild. One ``included`` change
    and the audit record ``campaign_included``, written before the commit.

    Refusals: 404 ``campaign_not_found``; 409 ``campaign_not_active``,
    ``not_related`` and ``already_overridden``; 422 ``reason_required``; 503
    ``audit_unavailable``.
    """
    by = await identify_caller(request)
    reason = _reason(body.reason)
    run_id = body.runId.strip()
    now = utcnow()
    async with request.app.state.db_sessionmaker() as db:
        await campaign_svc.ensure_fresh(db, audit=getattr(request.app.state, "audit", None))
        view = await campaign_svc.get_campaign(db, campaign_id)
        if view is None:
            raise _not_found()
        if view.status not in (campaign_svc.STATUS_OPEN, campaign_svc.STATUS_ENDED):
            raise api_error(
                409,
                "campaign_not_active",
                f"This campaign is {view.status}. Open the campaign that holds its activity.",
            )
        if run_id not in {r.run_id for r in view.needs_more_info}:
            raise api_error(
                409,
                "not_related",
                'This investigation is not under "Related, not proven" of this campaign.',
            )
        await _refuse_overridden(db, run_id)
        row = await db.get(Campaign, campaign_id)
        if row is None:
            raise _not_found()
        db.add(
            CampaignRunOverride(
                run_id=run_id,
                type=campaign_svc.OVERRIDE_INCLUDED,
                campaign_id=campaign_id,
                anchor_run_id=row.seed_run_id,
                by=by,
                reason=reason,
                created_at=now,
            )
        )
        db.add(
            decisions.change(
                campaign_id, decisions.CHANGE_INCLUDED, {"runId": run_id, "by": by}, now
            )
        )
        await _write_override(
            request,
            db,
            "campaign_included",
            {
                "campaign_id": campaign_id,
                "investigation_id": run_id,
                "anchor_run_id": row.seed_run_id,
                "reason": reason,
            },
            by,
            action="inclusion",
        )
        return await _fresh_out(request, db, campaign_id)


@router.post("/campaigns/{campaign_id}/overrides/{run_id}/undo", response_model=CampaignOut)
async def undo_override(request: Request, campaign_id: int, run_id: str) -> CampaignOut:
    """Undo an exclusion or an inclusion. A signed-in analyst may undo.

    The override goes, and the next rebuild reads the investigation as the
    links place it. The audit record ``campaign_override_undone`` is written
    before the commit.

    Refusals: 404 ``campaign_not_found`` and ``no_override``; 503
    ``audit_unavailable``.
    """
    by = await identify_caller(request)
    async with request.app.state.db_sessionmaker() as db:
        row = await db.get(Campaign, campaign_id)
        if row is None:
            raise _not_found()
        held = await db.scalar(
            select(CampaignRunOverride).where(
                CampaignRunOverride.run_id == run_id,
                CampaignRunOverride.campaign_id == campaign_id,
            )
        )
        if held is None:
            raise api_error(
                404, "no_override", "This campaign holds no exclusion or inclusion of it."
            )
        payload = {
            "campaign_id": campaign_id,
            "investigation_id": run_id,
            "type": held.type,
            "reason": held.reason,
        }
        await db.delete(held)
        await _write_override(request, db, "campaign_override_undone", payload, by, action="undo")
        return await _fresh_out(request, db, campaign_id)


async def _audit(request: Request, kind: str, payload: dict[str, Any], by: str) -> None:
    """One audit record. Best-effort: the write is already committed."""
    try:
        audit = getattr(request.app.state, "audit", None)
        if audit is not None:
            await audit.log_kind(AUDIT_SESSION, kind, payload, user=by)
    except Exception:
        _LOGGER.warning("%s audit write failed (continuing)", kind, exc_info=True)


__all__ = [
    "AuthorizeDraftOut",
    "AuthorizeIn",
    "CampaignCaseOut",
    "CampaignHuntOut",
    "CampaignLeadOut",
    "CampaignLinkOut",
    "CampaignOut",
    "CampaignRowCaseOut",
    "CampaignRowOut",
    "CampaignsOut",
    "CloseIn",
    "CloseScopeOut",
    "OverrideIn",
    "PartyBriefOut",
    "ReopenIn",
    "RevokeAuthorizationIn",
    "SinceDecisionOut",
    "authorize_campaign",
    "campaign_authorize_draft",
    "campaign_close_scope",
    "close_campaign",
    "exclude_from_campaign",
    "get_campaign",
    "include_in_campaign",
    "link_out",
    "list_campaigns",
    "reopen_campaign",
    "revoke_campaign_authorization",
    "undo_override",
]
