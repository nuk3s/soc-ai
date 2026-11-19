"""The authorization of a campaign: which investigations a campaign record covers.

The owner rule: an authorization covers what is demonstrably the same thing.
A campaign record (:func:`soc_ai.store.authorized_activity.create_for_campaign`)
lists the machines of one campaign, each an actor or a target, with a label,
a note and an expiry. It lists no rule.

An investigation is inside a campaign record when three things hold:

* its source is a listed actor,
* its target is a listed target,
* its event time is between the start of the record and its expiry.

The rule holds for an alert investigation and for a finding investigation,
at each stage. A finding investigation with a target and no source is inside
when its target is a listed target. Each machine that a finding names must be
listed too. A machine is matched by its machine key, read the one way a party
is read (:func:`soc_ai.campaigns.facts.machine_resolver`). A name never
matches.

Each other investigation that touches a listed machine is outside, with one
reason (``why``):

* ``source``: the source is no listed actor. A listed target as the source is
  outside, and so is an investigation with no source address.
* ``target``: the target is no listed target, or the alert is a hit of a
  deception sensor.
* ``machine``: an address of a listed machine now belongs to another machine,
  or the finding names a machine that is not listed, or a host by its name.
* ``expired``: the event time is after the expiry or before the start, or the
  investigation has no event time.

An inside investigation gets the mark of the rule-list form: the column
``investigations.authorization_id`` and the display copy in the report. Its
actions do not wait, it raises no bell row and no webhook, and it forms no
lead. Its verdict does not change. The triage model never reads a record.

The pure rules are :func:`why_outside` and :func:`judge`. The store reads are
:func:`ends_of` (the machines of each investigation now), :func:`mark_inside`
(the marks of stored investigations) and :func:`after_rebuild`. Any failure
in a caller gives no mark, so the investigation gets normal handling.
"""

from __future__ import annotations

import ipaddress
import logging
import re
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime
from types import SimpleNamespace
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from soc_ai.campaigns import decisions, facts
from soc_ai.campaigns.facts import chunked
from soc_ai.campaigns.types import KIND_ALERT, KIND_FINDING, TRUE_POSITIVE, naive_utc
from soc_ai.so_client.models import SoAlert
from soc_ai.store import authorized_activity as store
from soc_ai.store import first_line
from soc_ai.store.authorized_activity import Scope
from soc_ai.store.models import Campaign, CampaignChange, CampaignMember, Hunt, Investigation

_LOGGER = logging.getLogger(__name__)

WHY_SOURCE = "source"
WHY_TARGET = "target"
WHY_MACHINE = "machine"
WHY_EXPIRED = "expired"
WHYS = (WHY_SOURCE, WHY_TARGET, WHY_MACHINE, WHY_EXPIRED)

# One clause for each reason. The line of an outside investigation names it.
_WHY_CLAUSE: Mapping[str, str] = {
    WHY_SOURCE: "the source is not a listed actor",
    WHY_TARGET: "the target is not a listed target",
    WHY_MACHINE: "the investigation names a machine that the authorization does not list",
    WHY_EXPIRED: "the event time is outside the period of the authorization",
}

# How many merges the record follows to find the campaign that holds its machines.
_MERGE_HOPS = 8
_ACTIVE = "active"


@dataclass(frozen=True)
class RunEnds:
    """What the rules read of one investigation: its two ends now, its time and its names.

    ``source_address`` and ``target_address`` are the ends as the report
    states them: an address, a host name or None. ``source_key`` and
    ``target_key`` are the machines of the two addresses now, or None.
    ``named`` holds each host that a finding names, with its machine key or
    None. ``mentions`` holds each address and each known machine name in the
    text of the report, with the keys of the machines that carry it today.
    ``decoy`` is true for a hit of a deception sensor.
    """

    run_id: str
    kind: str
    source_address: str | None
    target_address: str | None
    source_key: str | None
    target_key: str | None
    event_time: datetime | None
    named: tuple[tuple[str, str | None], ...] = ()
    mentions: tuple[tuple[str, frozenset[str]], ...] = ()
    decoy: bool = False


# ── Pure rules ─────────────────────────────────────────────────────────────


def _address(value: str | None) -> str | None:
    try:
        return str(ipaddress.ip_address((value or "").strip()))
    except ValueError:
        return None


def _listed_addresses(scope: Scope) -> set[str]:
    return {a for p in scope.parties for raw in p.addresses if (a := _address(raw)) is not None}


def _end(
    scope: Scope, key: str | None, address: str | None, wanted: frozenset[str], why: str
) -> str | None:
    """None when the end is a listed machine of the role, else the reason."""
    if key is not None and key in wanted:
        return None
    listed = scope.actors | scope.targets
    normal = _address(address)
    if normal is not None and normal in _listed_addresses(scope) and key not in listed:
        # The address was an address of a listed machine. It belongs to
        # another machine now, or to no machine.
        return WHY_MACHINE
    return why


def why_outside(scope: Scope, ends: RunEnds) -> str | None:
    """None when the investigation is inside the campaign record, else the reason. Pure.

    The reasons in order: a deception sensor, the source, the target, a
    named machine, a machine in the text of the report, the time. A finding
    with no source skips the source.

    An event between a listed actor and a listed target is inside in both
    directions: the attack, and the answer of the target to the actor.

    The text of the report counts for an alert investigation and for a
    finding investigation. A report that names a third machine is about more
    than the activity between the listed machines, so it stays loud. An
    address that no machine carries, and a name that only other machines
    carry, are each a third machine.
    """
    if ends.decoy:
        return WHY_TARGET
    no_source = ends.kind == KIND_FINDING and not (ends.source_address or ends.source_key)
    # The answer of a listed target to a listed actor is between the same two
    # machines as the attack, so it is inside. A listed target that acts
    # against any other machine reads the checks below and stays loud.
    answer = not no_source and ends.source_key in scope.targets and ends.target_key in scope.actors
    if not answer:
        if not no_source:
            why = _end(scope, ends.source_key, ends.source_address, scope.actors, WHY_SOURCE)
            if why is not None:
                return why
        why = _end(scope, ends.target_key, ends.target_address, scope.targets, WHY_TARGET)
        if why is not None:
            return why
    listed = scope.actors | scope.targets
    if any(key is None or key not in listed for _host, key in ends.named):
        return WHY_MACHINE
    if any(not (keys & listed) for _host, keys in ends.mentions):
        return WHY_MACHINE
    at = ends.event_time
    if at is None or not (scope.starts_at <= at <= scope.expires_at):
        return WHY_EXPIRED
    return None


# The mention that stands for machine names that soc-ai could not read. It
# carries no machine, so the investigation is outside every record.
_NAMES_UNREAD = ("the machine names", frozenset[str]())


def mentions_of(
    texts: Iterable[str],
    host_names: Mapping[str, frozenset[str]] | None,
) -> list[tuple[str, frozenset[str] | None]]:
    """Each address and each known machine name in the text of a report. Pure.

    An address comes with None: the caller resolves it to its machine. A
    machine name, as a whole word in any case, comes with the keys of the
    machines that carry it. ``host_names`` is None when soc-ai could not read
    the Hosts data: nothing then shows what the names in the text are, and
    the one entry :data:`_NAMES_UNREAD` puts the investigation outside.
    """
    from soc_ai.agent import authorized_activity as report_rules  # noqa: PLC0415 - cycle

    if host_names is None:
        return [_NAMES_UNREAD]
    found: dict[str, frozenset[str] | None] = {}
    for text in texts:
        for _at, _literal, normal in report_rules._addresses_in(text):
            found.setdefault(normal, None)
        lowered = text.lower()
        for name, keys in host_names.items():
            if name in found or name not in lowered or _address(name) is not None:
                continue
            if re.search(rf"(?<![\w.-]){re.escape(name)}(?![\w-])", text, re.IGNORECASE):
                found[name] = frozenset(keys)
    return list(found.items())


def touches(scope: Scope, ends: RunEnds) -> bool:
    """Whether the investigation names a listed machine, by its key or by a listed address."""
    listed = scope.actors | scope.targets
    keys = {ends.source_key, ends.target_key, *(key for _host, key in ends.named)}
    if keys & listed:
        return True
    addresses = _listed_addresses(scope)
    hosts = (ends.source_address, ends.target_address, *(host for host, _key in ends.named))
    return any(_address(h) in addresses for h in hosts if h)


def judge(scopes: Sequence[Scope], ends: RunEnds) -> tuple[Scope, str | None] | None:
    """The campaign record that covers the investigation, or the one it is outside of. Pure.

    ``(scope, None)`` for the oldest record that covers it. Else
    ``(scope, why)`` for the oldest record whose machines it touches. None
    when it touches no listed machine. A revoked record and a record of the
    rule-list form are skipped.
    """
    live = sorted(
        (s for s in scopes if s.campaign_id is not None and s.revoked_at is None),
        key=lambda s: s.id,
    )
    outside: tuple[Scope, str | None] | None = None
    for scope in live:
        if not touches(scope, ends):
            continue
        why = why_outside(scope, ends)
        if why is None:
            return scope, None
        if outside is None:
            outside = (scope, why)
    return outside


def outside_line(label: str, why: str) -> str:
    """The one line of an investigation outside a campaign record."""
    clause = _WHY_CLAUSE.get(why, "one part of the authorization does not match")
    return f"This activity is outside the authorization {label}: {clause}."


# ── The machines of each investigation now ─────────────────────────────────


def _alert(payload: Any) -> SoAlert | None:
    if not isinstance(payload, Mapping):
        return None
    try:
        return SoAlert.model_validate(dict(payload))
    except Exception:
        return None


def _event_time(alert: SoAlert | None) -> datetime | None:
    return naive_utc(getattr(alert, "timestamp", None)) if alert is not None else None


async def _host_names(db: AsyncSession) -> Mapping[str, frozenset[str]] | None:
    """The machine names of the Hosts data, or None when the read fails."""
    try:
        return await store.machine_names(db)
    except Exception:
        _LOGGER.warning(
            "campaign authorization: the machine names are not readable, so each "
            "investigation is outside",
            exc_info=True,
        )
        return None


async def _finding_hosts(db: AsyncSession, invs: Sequence[Any]) -> dict[str, tuple[str, ...]]:
    """The hosts that the finding of each finding investigation names."""
    from soc_ai.store import investigations as inv_svc  # noqa: PLC0415 - light import

    groups = {inv.id: g for inv in invs if (g := inv_svc.finding_group_id(inv)) is not None}
    reports: dict[str, Any] = {}
    for ids in chunked(sorted({hunt_id for hunt_id, _ordinal in groups.values()})):
        rows = await db.execute(select(Hunt.id, Hunt.report).where(Hunt.id.in_(ids)))
        reports.update({str(h_id): report for h_id, report in rows.all()})
    out: dict[str, tuple[str, ...]] = {}
    for run_id, (hunt_id, ordinal) in groups.items():
        report = reports.get(hunt_id)
        listed = report.get("findings") if isinstance(report, dict) else None
        finding = (
            listed[ordinal] if isinstance(listed, list) and 0 <= ordinal < len(listed) else None
        )
        hosts = finding.get("hosts") if isinstance(finding, Mapping) else None
        out[run_id] = tuple(
            str(h).strip() for h in (hosts if isinstance(hosts, list) else []) if str(h).strip()
        )
    return out


def _ends(
    holder: Any, kind: str, alert: SoAlert | None, hosts: Sequence[str]
) -> tuple[str | None, str | None]:
    """The source and the target of an investigation.

    The ends that the report states (:func:`soc_ai.store.first_line.run_ends`).
    A report with no stated ends and a row with no addresses take the ends of
    the alert context, by the rule of the run: the finding rule for a finding.
    """
    report = holder.report if isinstance(holder.report, Mapping) else {}
    if isinstance(report.get(first_line.ENDS_KEY), Mapping) or alert is None:
        return first_line.run_ends(holder)
    if holder.src_ip or holder.dest_ip:
        return first_line.run_ends(holder)
    if kind == KIND_FINDING:
        return first_line.finding_ends(alert.source_ip, alert.destination_ip, hosts)
    return first_line.alert_ends(alert.source_ip, alert.destination_ip, alert.host_name)


async def ends_of(
    db: AsyncSession,
    invs: Sequence[Any],
    *,
    reports: Mapping[str, Mapping[str, Any]] | None = None,
    contexts: Mapping[str, Mapping[str, Any]] | None = None,
) -> dict[str, RunEnds]:
    """The ends of each alert and finding investigation, with the machines of today.

    ``reports`` holds the report of an investigation that the store does not
    hold yet: the finish of a run. ``contexts`` holds its alert context
    event. Without them the stored report and the stored context count. A
    lead investigation gets no entry.
    """
    from soc_ai.agent import authorized_activity as report_rules  # noqa: PLC0415 - cycle
    from soc_ai.agent.decision_templates import _alert_signals_decoy  # noqa: PLC0415 - heavy

    held_reports = reports or {}
    held_contexts = dict(contexts or {})
    wanted = [inv for inv in invs if facts.run_kind(inv) in (KIND_ALERT, KIND_FINDING)]
    missing = [inv.id for inv in wanted if inv.id not in held_contexts]
    for ids in chunked(missing):
        held_contexts.update(await facts._contexts(db, ids))
    named = await _finding_hosts(db, [i for i in wanted if facts.run_kind(i) == KIND_FINDING])
    host_names = await _host_names(db) if wanted else None
    rows: list[tuple[Any, str, SoAlert | None, tuple[str | None, str | None], datetime | None]] = []
    mentioned: dict[str, list[tuple[str, frozenset[str] | None]]] = {}
    addresses: set[str] = set()
    for inv in wanted:
        report = held_reports.get(inv.id)
        if report is None:
            report = inv.report if isinstance(inv.report, dict) else {}
        holder = SimpleNamespace(
            report=dict(report),
            src_ip=getattr(inv, "src_ip", None),
            dest_ip=getattr(inv, "dest_ip", None),
            host_name=getattr(inv, "host_name", None),
        )
        context = held_contexts.get(inv.id)
        alert = _alert(context.get("alert")) if isinstance(context, Mapping) else None
        kind = facts.run_kind(inv)
        ends = _ends(holder, kind, alert, named.get(inv.id, ()))
        at = first_line.event_time_of(holder) or _event_time(alert)
        rows.append((inv, kind, alert, ends, at))
        addresses.update(a for a in ends if a)
        addresses.update(named.get(inv.id, ()))
        mentioned[inv.id] = mentions_of(report_rules.report_texts(report), host_names)
        addresses.update(host for host, keys in mentioned[inv.id] if keys is None)
    machine = await facts.machine_resolver(db, [a for a in addresses if _address(a)])

    def key_of(host: str | None) -> str | None:
        ref = machine(_address(host)) if _address(host) is not None else None
        return ref.key if ref is not None else None

    out: dict[str, RunEnds] = {}
    for inv, kind, alert, (source, target), at in rows:
        out[inv.id] = RunEnds(
            run_id=inv.id,
            kind=kind,
            source_address=source,
            target_address=target,
            source_key=key_of(source),
            target_key=key_of(target),
            event_time=at,
            named=tuple((host, key_of(host)) for host in named.get(inv.id, ())),
            mentions=tuple(
                (host, keys if keys is not None else frozenset(filter(None, [key_of(host)])))
                for host, keys in mentioned.get(inv.id, ())
            ),
            decoy=alert is not None and bool(_alert_signals_decoy(alert)),
        )
    return out


# ── Stored investigations ──────────────────────────────────────────────────


async def campaign_scopes(db: AsyncSession, *, now: datetime | None = None) -> list[Scope]:
    """The campaign records in force: not revoked, and not long ended."""
    return [s for s in await store.in_force(db, now=now) if s.campaign_id is not None]


async def active_campaign(db: AsyncSession, campaign_id: int | None) -> Campaign | None:
    """The active campaign that holds the machines of a record, through its merges."""
    current = campaign_id
    for _hop in range(_MERGE_HOPS):
        if current is None:
            return None
        row = await db.get(Campaign, current)
        if row is None:
            return None
        if row.status == _ACTIVE:
            return row
        current = row.merged_into_id
    return None


async def true_positive_members(db: AsyncSession, campaign_id: int) -> list[Investigation]:
    """The true positive investigations of one campaign, in id order."""
    run_ids = (
        await db.scalars(
            select(CampaignMember.run_id).where(
                CampaignMember.campaign_id == campaign_id,
                CampaignMember.verdict_differs.is_(False),
            )
        )
    ).all()
    out: list[Investigation] = []
    for ids in chunked(sorted({str(r) for r in run_ids})):
        rows = await db.scalars(
            select(Investigation).where(
                Investigation.id.in_(ids),
                Investigation.verdict == TRUE_POSITIVE,
                Investigation.status == "complete",
            )
        )
        out.extend(rows.all())
    return sorted(out, key=lambda inv: inv.id)


async def answers(
    db: AsyncSession, scope: Scope, invs: Sequence[Investigation]
) -> dict[str, str | None]:
    """The answer of the record for each investigation: None inside, else the reason.

    An investigation whose ends soc-ai cannot read is outside with the
    reason ``source``: nothing shows that it is inside.
    """
    ends = await ends_of(db, invs)
    return {
        inv.id: why_outside(scope, ends[inv.id]) if inv.id in ends else WHY_SOURCE for inv in invs
    }


async def _holding(db: AsyncSession, invs: Iterable[Investigation]) -> set[str]:
    """The ids of the investigations whose authorization mark holds now."""
    held = list(invs)
    marks = await store.marks_for(db, [inv.authorization_id for inv in held])
    return {
        inv.id
        for inv in held
        if inv.authorization_id is not None
        and (mark := marks.get(int(inv.authorization_id))) is not None
        and mark.holds
    }


async def mark_inside(
    db: AsyncSession,
    audit: Any,
    scope: Scope,
    invs: Sequence[Investigation],
    *,
    now: datetime | None = None,
) -> list[str]:
    """Put the mark of the record on each inside investigation that holds no mark. The ids.

    Each one gets the column, the display copy and one audit record
    ``authorized_activity_matched``, through the path of the rule-list form
    (:func:`soc_ai.agent.authorized_activity.apply_to_stored_runs`). An
    investigation with a mark that holds keeps it.
    """
    from soc_ai.agent.authorized_activity import apply_to_stored_runs  # noqa: PLC0415 - heavy

    held = await _holding(db, invs)
    free = [inv for inv in invs if inv.id not in held]
    found = await answers(db, scope, free)
    inside = [inv for inv in free if found.get(inv.id, WHY_SOURCE) is None]
    await apply_to_stored_runs(db, audit, scope, inside, now=now)
    return [inv.id for inv in inside]


@dataclass(frozen=True)
class BeyondRun:
    """One true positive investigation of the campaign that the record does not cover."""

    inv: Investigation
    why: str
    ends: RunEnds | None


async def beyond_of(
    db: AsyncSession, scope: Scope, invs: Sequence[Investigation]
) -> list[BeyondRun]:
    """The investigations outside the record whose mark does not hold, in id order.

    An investigation with a mark that holds is quiet, so it is no activity
    beyond the authorization.
    """
    held = await _holding(db, invs)
    free = [inv for inv in invs if inv.id not in held]
    ends = await ends_of(db, free)
    out: list[BeyondRun] = []
    for inv in free:
        found = ends.get(inv.id)
        why = why_outside(scope, found) if found is not None else WHY_SOURCE
        if why is not None:
            out.append(BeyondRun(inv, why, found))
    return out


async def _known_beyond(db: AsyncSession, campaign_id: int) -> set[str]:
    rows = await db.scalars(
        select(CampaignChange.detail).where(
            CampaignChange.campaign_id == campaign_id,
            CampaignChange.type == decisions.CHANGE_BEYOND,
        )
    )
    return {
        str(detail.get("runId"))
        for detail in rows.all()
        if isinstance(detail, dict) and detail.get("runId")
    }


async def write_beyond(
    db: AsyncSession,
    campaign_id: int,
    beyond: Sequence[BeyondRun],
    *,
    now: datetime,
) -> int:
    """Add one ``beyond`` change for each investigation that has none yet. The caller commits."""
    known = await _known_beyond(db, campaign_id)
    added = 0
    for run in beyond:
        if run.inv.id in known:
            continue
        db.add(
            decisions.change(
                campaign_id, decisions.CHANGE_BEYOND, {"runId": run.inv.id, "why": run.why}, now
            )
        )
        added += 1
    return added


async def after_rebuild(db: AsyncSession, audit: Any, *, now: datetime) -> None:
    """The marks and the ``beyond`` changes of each campaign record in force, after a rebuild.

    Each inside investigation of the campaign of a record gets the mark. A
    campaign whose decision is this record gets one ``beyond`` change for
    each new investigation outside it. A record follows the merges of its
    campaign. A failure logs one warning and leaves the investigations with
    normal handling.
    """
    try:
        scopes = await campaign_scopes(db, now=now)
        for scope in scopes:
            row = await active_campaign(db, scope.campaign_id)
            if row is None:
                continue
            campaign_id, decided = (
                row.id,
                (
                    row.decision == decisions.DECISION_AUTHORIZED
                    and row.authorization_id == scope.id
                ),
            )
            invs = await true_positive_members(db, campaign_id)
            await mark_inside(db, audit, scope, invs, now=now)
            if decided:
                await write_beyond(db, campaign_id, await beyond_of(db, scope, invs), now=now)
                await db.commit()
    except Exception:
        _LOGGER.warning(
            "campaigns: soc-ai could not apply the campaign authorizations after the rebuild. "
            "The investigations keep normal handling.",
            exc_info=True,
        )
        try:
            await db.rollback()
        except Exception:
            _LOGGER.debug("campaigns: the rollback failed", exc_info=True)


async def revoke_record(
    db: AsyncSession, authorization_id: int, *, by: str, reason: str, now: datetime
) -> tuple[Any, bool]:
    """Revoke one campaign record and clear the decision of its campaign. The caller commits.

    The revoke ends every mark of the record: each reader asks whether the
    record holds, and a revoked record holds nothing. The campaign that holds
    the record as its decision loses the decision and gets one ``reopened``
    change with the cause ``revoked``. It then holds its investigations
    again and waits as one item. No investigation goes to the lead path.
    Returns the row and whether this call revoked it, as
    :func:`soc_ai.store.authorized_activity.revoke`.
    """
    row, changed = await store.revoke(
        db, authorization_id, by=by, reason=reason, now=now, commit=False
    )
    if row is None or not changed or row.campaign_id is None:
        return row, changed
    held = (
        await db.scalars(
            select(Campaign).where(
                Campaign.authorization_id == authorization_id,
                Campaign.decision == decisions.DECISION_AUTHORIZED,
            )
        )
    ).all()
    for campaign in held:
        decisions.write_revoked(db, campaign, by=by, now=now, label=getattr(row, "label", None))
    return row, changed


__all__ = [
    "WHYS",
    "WHY_EXPIRED",
    "WHY_MACHINE",
    "WHY_SOURCE",
    "WHY_TARGET",
    "BeyondRun",
    "RunEnds",
    "active_campaign",
    "after_rebuild",
    "answers",
    "beyond_of",
    "campaign_scopes",
    "ends_of",
    "judge",
    "mark_inside",
    "outside_line",
    "revoke_record",
    "touches",
    "true_positive_members",
    "why_outside",
    "write_beyond",
]
