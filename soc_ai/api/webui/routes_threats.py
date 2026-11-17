"""Confirmed threats: the true positive verdicts of a window, merged by affected machine.

H1 (2026-11-13). The Dashboard said "TRUE POSITIVES 24H 3" beside a card that
said "True positive 0", and no element named the three. 42 of the 53 true
positive runs of 30 days had one target, from three sources, and no page
said so. The Hunt Console did not state what the hunts found, and the page of
the attacked host listed three false positives first.

``GET /threats`` answers "what is bad now" for one window:

* It reads the true positive verdicts that stand: the latest run of each
  alert and of each hunt finding
  (:func:`soc_ai.store.investigations.standing_true_positives`), whose event
  is in the window. The owner, 2026-11-15: a verdict of today on an event
  of 17 days ago counted as a threat of the last 24 hours.
* It merges them by the affected machine. A run is inbound when its
  destination is internal: the destination is the affected machine. A run
  is outbound when its destination is external and its source is
  internal: the source is the affected machine. ``internal_cidrs`` decides
  what is internal. The inbound runs and the outbound runs of one machine
  are two groups, so a row states one direction.
* Two addresses and a host name of one machine are one affected machine,
  by the Hosts data (:mod:`soc_ai.store.first_line`).
* A group whose every run carries an authorization mark that holds is listed
  apart, under ``authorized``: nothing in it waits on the analyst. A group
  with one unmarked run stays a row.
* ``total`` counts the true positive runs of the window, marked ones
  included, so the Dashboard tile and the panel state one number.
* ``campaigns`` lists each active campaign with a true positive run of the
  window, the worst stage first (S5, 2026-11-14). The owner decided that the
  campaign is the unit of work of the analyst. A run of a listed campaign
  leaves ``rows`` and ``authorized``, and the campaign counts it. ``total``
  still counts it. With ``host``, a campaign is listed when the machine of
  the host is a party.

The work is bounded. One read takes the runs. The labels, the marks, the
event times and the waiting actions each take a fixed number of reads for
all runs, and no row takes a read of its own. The response holds at most
:data:`MAX_ROWS` rows.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any
from urllib.parse import urlencode

from fastapi import Query, Request
from pydantic import BaseModel, Field

from soc_ai.api.webui import routes_hunts, routes_meta
from soc_ai.api.webui._errors import api_error
from soc_ai.api.webui._shared import _iso_utc, router
from soc_ai.api.webui.routes_campaigns import CampaignRowOut
from soc_ai.api.webui.routes_campaigns import _row_out as _campaign_row_out
from soc_ai.campaigns import service as campaign_svc
from soc_ai.campaigns.types import STAGES
from soc_ai.secret_scrub import scrub_secrets
from soc_ai.store import authorized_activity as authorized_svc
from soc_ai.store import first_line as first_line_svc
from soc_ai.store import host_machines
from soc_ai.store import investigations as inv_svc
from soc_ai.store.auth import utcnow
from soc_ai.store.first_line import HostLabel
from soc_ai.store.models import Investigation
from soc_ai.triage_models import IMPACT_ORDER, stored_impact

_LOGGER = logging.getLogger(__name__)

# The window when the request names none: the last 24 hours.
DEFAULT_WINDOW = timedelta(hours=24)
# The most rows one response holds.
MAX_ROWS = 50
# The most sources and the most rule names one row lists.
MAX_SOURCES = 5
MAX_RULES = 3
# The most authorizations one row lists.
MAX_ROW_AUTHORIZATIONS = 3
# The impact of a true positive that states none. An older release stored no
# impact, and the list filter reads such a run the same way.
_UNSTATED = "unknown"
# The direction of a run, from the affected machine.
INBOUND = "inbound"
OUTBOUND = "outbound"


class ThreatWindowOut(BaseModel):
    """The window the response covers, as ISO UTC times."""

    since: str
    until: str


class ThreatHostOut(BaseModel):
    """The affected machine of a group, as the Hosts data names it.

    ``address`` is the address of the newest run of the group. It is the
    host name when the run names no address, and it is empty when the run
    names no host. ``name``, ``role`` and ``machineKey`` are null when the
    Hosts data holds no machine for the target.
    """

    address: str
    name: str | None = None
    role: str | None = None
    machineKey: str | None = None


class ThreatSourceOut(BaseModel):
    address: str
    name: str | None = None


class ThreatRowAuthorizationOut(BaseModel):
    """One authorization that marks runs of a row, with its count of runs."""

    id: int
    label: str
    # ``active`` or ``expired``. A revoked authorization marks nothing.
    state: str
    expiresAt: str
    # The runs of the row that this authorization marks.
    runs: int
    runsHref: str


class ThreatRowOut(BaseModel):
    """The true positive runs on one affected machine that need the analyst."""

    # The affected machine: the destination of an inbound run, the source
    # of an outbound run.
    target: ThreatHostOut
    # ``inbound``: the sources connect to the target. ``outbound``: the
    # target connects to the sources, which are external.
    direction: str = INBOUND
    # The first line of the newest run of the group, without the verdict
    # words: the impact and the two hosts. In a group that holds an
    # authorized run, the newest run outside every authorization.
    headline: str
    # The worst impact over the runs of the group: succeeded, attempted,
    # unknown, none. A run that states no impact counts as unknown.
    impact: str
    runs: int
    alertRuns: int
    findingRuns: int
    # The other ends of the runs of the group, the newest first. At most five.
    sources: list[ThreatSourceOut] = Field(default_factory=list)
    sourcesMore: int = 0
    # The rule names and the finding titles of the group, the newest first.
    # At most three.
    rules: list[str] = Field(default_factory=list)
    rulesMore: int = 0
    # The event time of the first and the last run, as ISO UTC. The run time
    # stands in for a run that holds no event time.
    firstSeen: str
    lastSeen: str
    # The recommended actions of the group that wait on the analyst, by the
    # needs-you rule. An authorized run waits on nothing.
    waitingActions: int = 0
    newestInvestigationId: str
    # The Investigations list, filtered to the true positives of this target
    # in the window.
    investigationsHref: str
    # The runs of the row that an authorization holds. They are in ``runs``
    # and wait on nothing. A row with every run authorized is in
    # ``authorized`` and has no row here.
    authorizedRuns: int = 0
    # The authorizations of those runs, the most runs first. At most three.
    authorizations: list[ThreatRowAuthorizationOut] = Field(default_factory=list)


class ThreatAuthorizationOut(BaseModel):
    id: int
    label: str
    # ``active`` or ``expired``. A revoked authorization marks nothing.
    state: str
    expiresAt: str


class AuthorizedThreatOut(BaseModel):
    """The runs of one authorization on one target, in a group that is all authorized."""

    authorization: ThreatAuthorizationOut
    target: ThreatHostOut
    direction: str = INBOUND
    runs: int
    lastSeen: str
    runsHref: str


class ThreatCampaignOut(CampaignRowOut):
    """One active campaign of the window: a row of ``GET /campaigns`` and three counts.

    The counts cover the true positive runs of the campaign that stand in
    the window. ``waiting`` counts those with an action that waits and no
    authorization that holds. A run that the campaign holds has no action
    that waits, because the analyst decides on the campaign. ``authorized``
    counts those with an authorization that holds.
    """

    investigations: int = 0
    waiting: int = 0
    authorized: int = 0


class ThreatsOut(BaseModel):
    window: ThreatWindowOut
    # The runs in no listed campaign, merged by affected machine.
    rows: list[ThreatRowOut] = Field(default_factory=list)
    authorized: list[AuthorizedThreatOut] = Field(default_factory=list)
    # The true positive runs of the window, marked ones included. With the
    # ``host`` filter, the runs that name that host. A run of a campaign
    # counts here too.
    total: int = 0
    # The active campaigns with a true positive run in the window, the worst
    # stage first, then the newest last event.
    campaigns: list[ThreatCampaignOut] = Field(default_factory=list)


@dataclass
class _Run:
    """One run with what the merge reads of it."""

    inv: Investigation
    # The other end of the run. None when the run names one host.
    source: str | None
    # The affected machine.
    target: str | None
    seen: datetime
    impact: str
    mark: authorized_svc.Mark | None = None

    @property
    def authorized(self) -> bool:
        return self.mark is not None and self.mark.holds


@dataclass
class _Group:
    """The runs on one affected machine in one direction, newest first."""

    key: str
    direction: str = INBOUND
    runs: list[_Run] = field(default_factory=list)

    @property
    def last_seen(self) -> datetime:
        return max(run.seen for run in self.runs)


def _group_key(target: str | None, label: HostLabel | None, run_id: str) -> str:
    """One key for each target machine.

    The machine key when the Hosts data holds the target, so two addresses
    and a name of one machine merge. Else the value itself. A run that names
    no host is its own group.
    """
    if label is not None and label.machine_key:
        return f"machine:{label.machine_key}"
    if target:
        return f"value:{target.casefold()}"
    return f"run:{run_id}"


def _is_internal(value: str, label: HostLabel | None, settings: Any) -> bool:
    """True when *value* is inside ``internal_cidrs``.

    A host name counts by the address that the Hosts data holds for it. A
    name with no address names a machine of the grid, so it is internal.
    """
    address = value if first_line_svc.is_address(value) else (label.address if label else None)
    if not address:
        return True
    return bool(settings.network_is_internal(address))


def _direction(
    source: str | None, target: str | None, labels: dict[str, HostLabel], settings: Any
) -> str:
    """``outbound`` when the destination is external and the source is internal."""
    if not source or not target or source == target:
        return INBOUND
    if _is_internal(target, labels.get(target), settings):
        return INBOUND
    if _is_internal(source, labels.get(source), settings):
        return OUTBOUND
    return INBOUND


# The tag an older Oracle run put at the start of its headline.
_ORACLE_TAG = re.compile(r"^\s*\[oracle adjudicated\]\s*", re.IGNORECASE)
# A sentence about the verdict machinery: a raw verdict key, or the local
# verdict that the Oracle weighed.
_VERDICT_TALK = re.compile(
    r"\b(?:needs_more_info|true_positive|false_positive|inconclusive)\b|\blocal verdict\b",
    re.IGNORECASE,
)


# A finding run can open with a sentence about the claim: "The finding's core
# claim is correct" (production run 01M7BMRG7WEP2H7KF4FYAZP5NK). That sentence
# states nothing that happened. The row then states the finding title.
_CLAIM_TALK = re.compile(
    r"^\W*the (?:finding(?:'s|\u2019s)?|claim)\b[^.]{0,60}"
    r"\b(?:correct|confirmed|holds|stands|accurate|valid|true|supported)\b",
    re.IGNORECASE,
)


def _what_happened(inv: Investigation, labels: Any, mark: authorized_svc.Mark | None = None) -> str:
    """What happened, in the sentence of the run.

    The row already states the hosts and the impact in its own cells. The
    first line of the run repeats both, so a row read "Impact: not stated.
    <host> to <host>." and said nothing more (production, 2026-11-13). The
    headline of the run comes first, then the first sentence of its summary.
    The first line is the fallback for a run that stored neither.

    An older Oracle run starts its headline with "[Oracle adjudicated]" and
    talks about "the local needs_more_info verdict". The tag goes. A
    sentence that still names a raw verdict key or the local verdict states
    the rule name of the run, the finding title for a finding run.

    A run whose authorization holds drops each sentence that denies an
    authorization (:func:`authorized_svc.run_text_for_mark`).
    """
    stated = authorized_svc.run_text_for_mark((inv.rationale or "").strip(), mark)
    if not stated:
        summary = authorized_svc.run_text_for_mark((inv.summary or "").strip(), mark)
        if summary:
            first, dot, _rest = summary.partition(". ")
            stated = f"{first}." if dot else first
    if not stated:
        return first_line_svc.headline(first_line_svc.of_run(inv, labels))
    stated = _ORACLE_TAG.sub("", stated).strip()
    if _VERDICT_TALK.search(stated) or _CLAIM_TALK.search(stated):
        return (inv.rule_name or "").strip() or stated
    return stated


def _host_out(value: str | None, label: HostLabel | None) -> ThreatHostOut:
    address = value or ""
    if value and not first_line_svc.is_address(value) and label is not None and label.address:
        # The run names the host by name. The Hosts data holds its address.
        address = label.address
    return ThreatHostOut(
        address=address,
        name=label.name if label is not None else None,
        role=label.role if label is not None else None,
        machineKey=label.machine_key if label is not None else None,
    )


def _sources(runs: list[_Run], labels: dict[str, HostLabel]) -> tuple[list[ThreatSourceOut], int]:
    """The distinct sources of the runs, newest first, and the count left out."""
    seen: dict[str, ThreatSourceOut] = {}
    for run in runs:
        if not run.source:
            continue
        label = labels.get(run.source)
        key = _group_key(run.source, label, run.inv.id)
        if key not in seen:
            host = _host_out(run.source, label)
            seen[key] = ThreatSourceOut(address=host.address, name=host.name)
    listed = list(seen.values())
    return listed[:MAX_SOURCES], max(0, len(listed) - MAX_SOURCES)


def _rules(runs: list[_Run]) -> tuple[list[str], int]:
    """The distinct rule names and finding titles of the runs, newest first."""
    names = list(dict.fromkeys(name for run in runs if (name := (run.inv.rule_name or "").strip())))
    return [scrub_secrets(name) for name in names[:MAX_RULES]], max(0, len(names) - MAX_RULES)


def _worst_impact(runs: list[_Run]) -> str:
    return min((run.impact for run in runs), key=IMPACT_ORDER.index)


def _investigations_href(target: ThreatHostOut, value: str | None, window: ThreatWindowOut) -> str:
    """The console link to the true positives of one target in the window."""
    params: dict[str, str] = {"verdict": "true_positive"}
    entity = target.address or (value or "")
    if entity:
        params["entity"] = entity
        if target.name:
            params["entity_label"] = target.name
    params.update({"range": "custom", "from": window.since, "to": window.until})
    return f"/investigations?{urlencode(params)}"


def _window(since: datetime | None, until: datetime | None) -> tuple[datetime, datetime]:
    """The window as naive UTC. The default is the 24 hours before the upper bound."""
    end = routes_hunts._naive_utc(until) or utcnow()
    start = routes_hunts._naive_utc(since) or end - DEFAULT_WINDOW
    if start > end:
        raise api_error(
            422, "bad_window", "The window ends before it starts. Check since and until."
        )
    return start, end


async def _host_group_key(db: Any, host: str, settings: Any) -> str:
    """The key of the ``host`` filter: a machine key, an address or a name.

    The same key the merge gives a target, so the filter and the merge agree
    on what one host is. An address reads the Hosts data as a target does. A
    machine key and a name resolve to their machine. A value that names no
    machine filters on itself.
    """
    if first_line_svc.is_address(host):
        labels = await first_line_svc.labels_for_settings(db, [host], settings)
        return _group_key(host, labels.get(host), "")
    membership = await host_machines.resolve_membership(db, host)
    if membership is not None:
        return f"machine:{membership.key}"
    return f"value:{host.casefold()}"


@dataclass(frozen=True)
class _CampaignCounts:
    """One listed campaign and the counts over its runs of the window."""

    row: campaign_svc.CampaignRow
    investigations: int
    waiting: int
    authorized: int


@dataclass
class _Read:
    """What one request reads from the store."""

    groups: dict[str, _Group]
    labels: dict[str, HostLabel]
    # Run id to the count of its recommended actions that wait on the analyst.
    waiting: dict[str, int]
    total: int
    campaigns: list[_CampaignCounts] = field(default_factory=list)


async def _party_campaigns(db: Any, host_key: str) -> set[int]:
    """The active campaigns where the machine of the ``host`` filter is a party."""
    prefix = "machine:"
    if not host_key.startswith(prefix):
        return set()
    found = await campaign_svc.campaigns_of_machine(db, [host_key[len(prefix) :]])
    return {c.id for c in found}


def _stage_rank(stage: str | None) -> int:
    """The worst stage has the highest rank. No stage has rank 0."""
    return STAGES.index(stage) + 1 if stage in STAGES else 0


def _campaign_counts(
    rows: list[campaign_svc.CampaignRow],
    runs: list[Investigation],
    links: dict[str, campaign_svc.CampaignLink],
    marks: dict[int, authorized_svc.Mark],
    waiting: dict[str, int],
) -> list[_CampaignCounts]:
    """The counts of each listed campaign, the worst stage first, then the newest."""
    by_campaign: dict[int, list[Investigation]] = {}
    for inv in runs:
        by_campaign.setdefault(links[inv.id].id, []).append(inv)
    out: list[_CampaignCounts] = []
    for row in rows:
        held = by_campaign.get(row.id, [])
        marked = {inv.id for inv in held if _holds(marks.get(inv.authorization_id or 0))}
        out.append(
            _CampaignCounts(
                row=row,
                investigations=len(held),
                waiting=sum(
                    1 for inv in held if inv.id not in marked and waiting.get(inv.id, 0) > 0
                ),
                authorized=len(marked),
            )
        )
    out.sort(key=lambda c: (_stage_rank(c.row.stage), c.row.last_event, c.row.id), reverse=True)
    return out


def _holds(mark: authorized_svc.Mark | None) -> bool:
    return mark is not None and mark.holds


async def _read(request: Request, start: datetime, end: datetime, host: str) -> _Read:
    """The runs of the window in their groups, with the labels and the waiting actions."""
    settings = request.app.state.settings
    async with request.app.state.db_sessionmaker() as db:
        found, total = await inv_svc.standing_true_positives(db, since=start, until=end)
        ends = {inv.id: first_line_svc.run_ends(inv) for inv in found}
        labels = await first_line_svc.labels_for_settings(
            db, [value for pair in ends.values() for value in pair], settings
        )
        marks = await authorized_svc.marks_for(db, [inv.authorization_id for inv in found])
        host_key = await _host_group_key(db, host, settings) if host else None
        groups: dict[str, _Group] = {}
        for inv in found:  # newest first
            source, target = ends[inv.id]
            target = target or source
            direction = _direction(source, target, labels, settings)
            affected, other = (source, target) if direction == OUTBOUND else (target, source)
            host_part = _group_key(affected, labels.get(affected) if affected else None, inv.id)
            if host_key is not None and host_key not in (
                host_part,
                _group_key(other, labels.get(other) if other else None, inv.id),
            ):
                # The run names the host at neither end.
                continue
            key = f"{direction}|{host_part}"
            groups.setdefault(key, _Group(key=key, direction=direction)).runs.append(
                _Run(
                    inv=inv,
                    source=other if other != affected else None,
                    target=affected,
                    # The time of the event (migration 0072): the window
                    # bounds it, so the first and last seen times are in it.
                    seen=inv.event_at or inv.created_at,
                    impact=stored_impact(inv.report, inv.verdict) or _UNSTATED,
                    mark=marks.get(inv.authorization_id or 0),
                )
            )
        kept = [run for group in groups.values() for run in group.runs]
        # The campaigns of the window. A run of a listed campaign leaves the
        # rows. With the host filter, a campaign is listed when the machine
        # of the host is a party, and a run of another campaign stays a row.
        links = await campaign_svc.links_of(db, [inv.id for inv in found])
        listed = {link.id for link in links.values()}
        if host_key is not None:
            listed &= await _party_campaigns(db, host_key)
        in_campaign = [inv for inv in found if inv.id in links and links[inv.id].id in listed]
        moved = {inv.id for inv in in_campaign}
        # The waiting actions, by the needs-you rule. One call for all runs.
        unmarked = {run.inv.id: run.inv for run in kept if not run.authorized}
        for inv in in_campaign:
            if not _holds(marks.get(inv.authorization_id or 0)):
                unmarked.setdefault(inv.id, inv)
        waiting = await routes_meta.pending_actions_by_run(
            db, list(unmarked.values()), state=request.app.state
        )
        rows = await campaign_svc.list_campaigns(db, ids=listed) if listed else []
    counted = len(kept) if host_key is not None else total
    for key in list(groups):
        groups[key].runs = [run for run in groups[key].runs if run.inv.id not in moved]
        if not groups[key].runs:
            del groups[key]
    return _Read(
        groups=groups,
        labels=labels,
        waiting=waiting,
        total=counted,
        campaigns=_campaign_counts(rows, in_campaign, links, marks, waiting),
    )


def _row_out(
    group: _Group, open_runs: list[_Run], read: _Read, window: ThreatWindowOut
) -> ThreatRowOut:
    """The row of a group that holds a run outside every authorization."""
    lead = open_runs[0]
    target = _host_out(lead.target, read.labels.get(lead.target) if lead.target else None)
    sources, sources_more = _sources(group.runs, read.labels)
    rules, rules_more = _rules(group.runs)
    alert_runs = sum(1 for run in group.runs if inv_svc.alert_group_id(run.inv) is not None)
    return ThreatRowOut(
        target=target,
        direction=group.direction,
        headline=scrub_secrets(_what_happened(lead.inv, read.labels, lead.mark)),
        impact=_worst_impact(group.runs),
        runs=len(group.runs),
        alertRuns=alert_runs,
        findingRuns=len(group.runs) - alert_runs,
        sources=sources,
        sourcesMore=sources_more,
        rules=rules,
        rulesMore=rules_more,
        firstSeen=_iso_utc(min(run.seen for run in group.runs)),
        lastSeen=_iso_utc(group.last_seen),
        waitingActions=sum(read.waiting.get(run.inv.id, 0) for run in open_runs),
        newestInvestigationId=lead.inv.id,
        investigationsHref=_investigations_href(target, lead.target, window),
        authorizedRuns=sum(1 for run in group.runs if run.authorized),
        authorizations=_row_authorizations(group.runs),
    )


def _row_authorizations(runs: list[_Run]) -> list[ThreatRowAuthorizationOut]:
    """The authorizations that hold runs of a row, the most runs first.

    A row that holds 9 authorized runs of 22 said nothing of the 9
    (production, 2026-11-13). Each entry counts its runs and links to them.
    """
    by_mark: dict[int, list[_Run]] = {}
    for run in runs:
        if run.authorized and run.mark is not None:
            by_mark.setdefault(run.mark.id, []).append(run)
    ranked = sorted(by_mark.items(), key=lambda pair: (-len(pair[1]), pair[0]))
    out: list[ThreatRowAuthorizationOut] = []
    for mark_id, marked in ranked[:MAX_ROW_AUTHORIZATIONS]:
        mark = marked[0].mark
        if mark is None:
            continue
        out.append(
            ThreatRowAuthorizationOut(
                id=mark.id,
                label=scrub_secrets(mark.label),
                state=mark.state,
                expiresAt=_iso_utc(mark.expires_at),
                runs=len(marked),
                runsHref=_authorization_runs_href(mark_id),
            )
        )
    return out


def _authorization_runs_href(mark_id: int) -> str:
    """The console link to the runs of one authorization."""
    return f"/investigations?authorization={mark_id}&range=all"


@router.get("/threats", response_model=ThreatsOut)
async def list_threats(
    request: Request,
    since: datetime | None = None,
    until: datetime | None = None,
    host: str | None = Query(None, max_length=200),
) -> ThreatsOut:
    """The confirmed threats of a window, merged by affected machine.

    ``since`` and ``until`` are ISO times, the window of the page. A time
    with no offset is UTC. The default window is the last 24 hours. The
    bounds are inclusive, and they bound the time of the event that a run
    judges (``event_at``). A verdict of today on an event of 10 days ago is
    no row of the last 24 hours: Needs you and the campaign changes state it.

    ``host`` keeps the runs that name one host at either end: a machine
    key, an address or a host name. The rows still merge by affected
    machine, so an internal host that attacks another internal host shows
    under the host it reached. A host that connects to an external command
    server is the affected machine of an outbound row. ``total`` then
    counts the runs that name the host.

    ``direction`` is ``inbound`` when the destination of the runs is
    internal, and ``outbound`` when the destination is external and the
    source is internal. The rows and the ``authorized`` entries carry it.

    ``rows`` holds the groups that need the analyst, at most 50, in this
    order: the impact (succeeded, attempted, unknown, none), then the
    waiting actions, then the last seen time. ``authorized`` holds the
    groups whose every run matched an authorization that an analyst did not
    revoke, one entry for each authorization, affected machine and direction.

    ``campaigns`` holds each active campaign with a true positive run in the
    window: movement, action, access, attempt, reconnaissance, no stage, then
    the newest last event. Each entry is a row of ``GET /campaigns`` with
    ``investigations``, ``waiting`` and ``authorized``. The runs of a listed
    campaign are in no row and in no ``authorized`` entry. With ``host``, a
    campaign is listed when the machine of the host is a party.
    """
    start, end = _window(since, until)
    window = ThreatWindowOut(since=_iso_utc(start), until=_iso_utc(end))
    read = await _read(request, start, end, (host or "").strip())
    ranked: list[tuple[tuple[int, int, float], ThreatRowOut]] = []
    authorized: list[tuple[datetime, AuthorizedThreatOut]] = []
    for group in read.groups.values():
        open_runs = [run for run in group.runs if not run.authorized]
        if not open_runs:
            authorized.extend(_authorized_out(group, read.labels))
            continue
        row = _row_out(group, open_runs, read, window)
        order = (
            IMPACT_ORDER.index(row.impact),
            -row.waitingActions,
            -group.last_seen.timestamp(),
        )
        ranked.append((order, row))
    ranked.sort(key=lambda pair: pair[0])
    authorized.sort(key=lambda pair: pair[0], reverse=True)
    return ThreatsOut(
        window=window,
        rows=[row for _order, row in ranked[:MAX_ROWS]],
        authorized=[entry for _seen, entry in authorized],
        total=read.total,
        campaigns=[
            ThreatCampaignOut(
                **_campaign_row_out(c.row).model_dump(),
                investigations=c.investigations,
                waiting=c.waiting,
                authorized=c.authorized,
            )
            for c in read.campaigns
        ],
    )


def _authorized_out(
    group: _Group, labels: dict[str, HostLabel]
) -> list[tuple[datetime, AuthorizedThreatOut]]:
    """One entry for each authorization that marks runs of an all-authorized group.

    Each entry comes with its last seen time, for the order of the list.
    """
    by_mark: dict[int, list[_Run]] = {}
    for run in group.runs:
        if run.mark is not None:
            by_mark.setdefault(run.mark.id, []).append(run)
    out: list[tuple[datetime, AuthorizedThreatOut]] = []
    for mark_id, runs in by_mark.items():
        mark = runs[0].mark
        if mark is None:
            continue
        lead = runs[0]
        last_seen = max(run.seen for run in runs)
        entry = AuthorizedThreatOut(
            authorization=ThreatAuthorizationOut(
                id=mark.id,
                label=mark.label,
                state=mark.state,
                expiresAt=_iso_utc(mark.expires_at),
            ),
            target=_host_out(lead.target, labels.get(lead.target) if lead.target else None),
            direction=group.direction,
            runs=len(runs),
            lastSeen=_iso_utc(last_seen),
            runsHref=_authorization_runs_href(mark_id),
        )
        out.append((last_seen, entry))
    return out


__all__ = [
    "MAX_ROWS",
    "AuthorizedThreatOut",
    "ThreatCampaignOut",
    "ThreatHostOut",
    "ThreatRowAuthorizationOut",
    "ThreatRowOut",
    "ThreatSourceOut",
    "ThreatWindowOut",
    "ThreatsOut",
    "list_threats",
]
