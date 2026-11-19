"""The rule prior's store: the history it reads and the decisions it records.

The rung itself lives in :mod:`soc_ai.agent.rule_prior`. This module holds
the SQL: a rule's model-backed runs, the names of the external end that their
stored alert contexts hold, its analyst overrides, the leads and the
observations on a host, and the ``rule_prior_decisions`` rows (migration
0058) with the suspension they carry.
"""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy import and_, case, func, or_, select, update
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import load_only

from soc_ai.store.auth import utcnow
from soc_ai.store.investigations import PROMOTED_KINDS, not_backtest, not_hunt_subject
from soc_ai.store.leads import CLOSED_STATUSES
from soc_ai.store.models import (
    Campaign,
    CampaignParty,
    EntityObservation,
    Investigation,
    InvestigationEvent,
    Lead,
    RulePriorDecision,
)

# The class a rule-prior run records. Kept as a string here so the store does
# not import the agent package (soc_ai.agent.budget.RULE_PRIOR).
RULE_PRIOR_CLASS = "rule_prior"
# The two reasons of a covered alert (soc_ai.agent.rule_prior, safeguard 1):
# both addresses internal, or one external address that the rule already knows
# on the same internal machine.
COVERED = "covered"
COVERED_KNOWN_EXTERNAL = "covered_known_external"

_ANALYST_RESOLUTIONS = ("chat", "manual")


async def model_backed_runs(
    db: AsyncSession, rule_name: str, *, since: datetime
) -> list[Investigation]:
    """The rule's completed model-backed runs since ``since``, newest first.

    Model-backed means a model wrote the verdict. A rule-prior run did not,
    so it never feeds the prior that produced it. A pipeline fallback is a
    failure, not a verdict. A promotion and a synthetic evaluation are not
    runs of the rule at all. A backtest replay is a measurement on an alert
    an analyst already closed, so it never teaches the prior.
    """
    rows = await db.scalars(
        select(Investigation)
        .options(
            load_only(
                Investigation.id,
                Investigation.verdict,
                Investigation.confidence,
                Investigation.created_at,
                Investigation.run_class,
                Investigation.src_ip,
                Investigation.dest_ip,
                raiseload=True,
            )
        )
        .where(
            Investigation.rule_name == rule_name,
            Investigation.status == "complete",
            Investigation.verdict.is_not(None),
            Investigation.created_at >= since,
            Investigation.is_fallback.isnot(True),
            func.coalesce(Investigation.run_class, "") != RULE_PRIOR_CLASS,
            Investigation.kind.not_in(PROMOTED_KINDS),
            Investigation.is_synth_eval.isnot(True),
            not_hunt_subject(),
            not_backtest(),
        )
        .order_by(Investigation.created_at.desc(), Investigation.id.desc())
    )
    return list(rows.all())


# The event kinds that hold the alert context of a run.
_CONTEXT_KINDS = ("alert_context", "enriched_alert_context")
# The fields of a stored alert context that name the external end of the flow:
# the TLS server name, the HTTP host and the DNS query. The alert carries them
# when its own document holds them. ``typed_zeek`` rolls up the Zeek records
# of the same community id only (soc_ai.tools.get_alert_context), so a name
# there names the flow of the alert and never another flow of the host.
_ALERT_NAME_FIELDS = ("zeek_ssl_server_name", "zeek_http_host", "zeek_dns_query", "dns_query")
_TYPED_NAME_FIELDS = ("sni_servers", "http_hosts", "dns_queries")
_NAMES_PER_FIELD = 32
_NAME_CHUNK = 100
# A host name: labels of letters, digits, hyphens and underscores. Anything
# else (a Zeek "-", a URL, a space) is no name, and gives no match.
_HOST_NAME = re.compile(
    r"[a-z0-9_](?:[a-z0-9_-]*[a-z0-9_])?(?:\.[a-z0-9_](?:[a-z0-9_-]*[a-z0-9_])?)*"
)


def normalize_name(value: Any) -> str | None:
    """A name of the external end, in one form, or None when it is no name.

    Lower case, no trailing dot, no port. An address literal is no name: the
    address match reads addresses.
    """
    if not isinstance(value, str):
        return None
    name = value.strip().lower().rstrip(".")
    host, sep, port = name.rpartition(":")
    if sep and port.isdigit() and host and ":" not in host:
        name = host
    if not name or len(name) > 253 or not _HOST_NAME.fullmatch(name):
        return None
    if all(part.isdigit() for part in name.split(".")):
        return None
    return name


def context_names(payload: Any) -> frozenset[str]:
    """The names of the external end in one stored alert context. Never raises."""
    if not isinstance(payload, Mapping):
        return frozenset()
    out: set[str] = set()
    alert = payload.get("alert")
    if isinstance(alert, Mapping):
        for key in _ALERT_NAME_FIELDS:
            name = normalize_name(alert.get(key))
            if name:
                out.add(name)
    typed = payload.get("typed_zeek")
    if isinstance(typed, Mapping):
        for key in _TYPED_NAME_FIELDS:
            values = typed.get(key)
            if not isinstance(values, list):
                continue
            for value in values[:_NAMES_PER_FIELD]:
                name = normalize_name(value)
                if name:
                    out.add(name)
    return frozenset(out)


async def stored_external_names(
    db: AsyncSession, run_ids: Sequence[str]
) -> dict[str, frozenset[str]]:
    """The names of the external end in the last stored alert context of each run.

    A run with no stored context, or a context that names nothing, is absent
    or maps to the empty set. Either one gives no name match.
    """
    ids = [r for r in dict.fromkeys(run_ids) if r]
    out: dict[str, frozenset[str]] = {}
    for start in range(0, len(ids), _NAME_CHUNK):
        chunk = ids[start : start + _NAME_CHUNK]
        last = (
            select(func.max(InvestigationEvent.id))
            .where(
                InvestigationEvent.investigation_id.in_(chunk),
                InvestigationEvent.kind.in_(_CONTEXT_KINDS),
            )
            .group_by(InvestigationEvent.investigation_id)
        )
        rows = await db.execute(
            select(InvestigationEvent.investigation_id, InvestigationEvent.payload).where(
                InvestigationEvent.id.in_(last)
            )
        )
        for run_id, payload in rows.all():
            out[str(run_id)] = context_names(payload)
    return out


def _address(value: Any) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    if not isinstance(value, str):
        return None
    try:
        return ipaddress.ip_address(value.strip())
    except ValueError:
        return None


# The decision of a campaign that an analyst closed (soc_ai.campaigns.decisions).
_DECISION_CLOSED = "closed"


async def in_open_campaign(db: AsyncSession, addresses: Iterable[str], *, now: datetime) -> bool:
    """Whether one of ``addresses`` belongs to a party of an open campaign.

    Open is what the campaign page states (``campaign_svc.api_status``). A
    campaign that an analyst closed holds no machine: the analyst decided
    that its activity is over. A campaign with no decision and a campaign
    with an authorization hold their machines. The
    read takes the stored rows of ``campaigns`` and ``campaign_parties``. It
    never rebuilds a campaign, so a sweep costs one query. A party matches by
    its address list, or by its ``ip:`` machine key when the Hosts data knows
    the machine by its address only. ``now`` is naive UTC.
    """
    # The campaign service imports this package; a lazy import keeps the store
    # free of a cycle.
    from soc_ai.campaigns.service import (  # noqa: PLC0415
        STATUS_ACTIVE,
        STATUS_OPEN,
        api_status,
    )

    wanted = {a for a in (_address(v) for v in addresses) if a is not None}
    if not wanted:
        return False
    rows = await db.execute(
        select(Campaign, CampaignParty.machine_key, CampaignParty.addresses)
        .options(
            load_only(
                Campaign.id,
                Campaign.status,
                Campaign.last_event,
                Campaign.last_alert_at,
                Campaign.decision,
            )
        )
        .join(CampaignParty, CampaignParty.campaign_id == Campaign.id)
        .where(Campaign.status == STATUS_ACTIVE)
    )
    for campaign, machine_key, held in rows.all():
        if campaign.decision == _DECISION_CLOSED:
            continue
        party = {_address(v) for v in (held if isinstance(held, list) else [])}
        if isinstance(machine_key, str) and machine_key.startswith("ip:"):
            party.add(_address(machine_key[3:]))
        if wanted & party and api_status(campaign, now) == STATUS_OPEN:
            return True
    return False


async def rule_has_analyst_override(db: AsyncSession, rule_name: str) -> bool:
    """Whether an analyst ever overrode a verdict of this rule, at any age.

    An override is a chat or a manual resolution (``investigations.resolve``).
    The whole history counts, not a recent window: one old correction says the
    model got this rule wrong once, and the prior must never paper over it.
    """
    # The JSON index renders json_extract on SQLite and ->> on PostgreSQL.
    resolved_via = Investigation.report["resolution"]["resolved_via"].as_string()
    hit = await db.scalar(
        select(Investigation.id)
        .where(Investigation.rule_name == rule_name, resolved_via.in_(_ANALYST_RESOLUTIONS))
        .limit(1)
    )
    return hit is not None


async def hosts_have_tier2_signal(
    db: AsyncSession, hosts: Iterable[str], *, now: datetime, fresh_hours: int
) -> bool:
    """Whether any of ``hosts`` carries an open lead or a fresh observation.

    Fresh means the observed event time, else the record time, falls inside
    the last ``fresh_hours``. A shadow observation counts too: a detector in
    shadow that fired on the host is still a reason to look.
    """
    keys = sorted({h for h in hosts if h})
    if not keys:
        return False
    cutoff = now - timedelta(hours=fresh_hours)
    fresh = await db.scalar(
        select(EntityObservation.id)
        .where(
            EntityObservation.entity_key.in_(keys),
            func.coalesce(EntityObservation.observed_at, EntityObservation.born_at) >= cutoff,
        )
        .limit(1)
    )
    if fresh is not None:
        return True
    via_observation = await db.scalar(
        select(Lead.id)
        .join(EntityObservation, EntityObservation.lead_id == Lead.id)
        .where(
            EntityObservation.entity_key.in_(keys),
            Lead.status.not_in(tuple(CLOSED_STATUSES)),
        )
        .limit(1)
    )
    if via_observation is not None:
        return True
    open_entities = await db.scalars(
        select(Lead.entities_json).where(Lead.status.not_in(tuple(CLOSED_STATUSES)))
    )
    wanted = set(keys)
    for entities in open_entities.all():
        for entity in entities or []:
            if isinstance(entity, (list, tuple)) and len(entity) == 2 and str(entity[1]) in wanted:
                return True
    return False


async def rule_is_suspended(db: AsyncSession, rule_name: str) -> bool:
    """A disagreement on a covered alert stands with no analyst clearance."""
    hit = await db.scalar(
        select(RulePriorDecision.id)
        .where(
            RulePriorDecision.rule_name == rule_name,
            RulePriorDecision.agree.is_(False),
            RulePriorDecision.cleared_at.is_(None),
        )
        .limit(1)
    )
    return hit is not None


async def record_decision(db: AsyncSession, **fields: Any) -> RulePriorDecision:
    row = RulePriorDecision(**fields)
    db.add(row)
    await db.commit()
    await db.refresh(row)
    return row


async def settle_decision(
    db: AsyncSession,
    decision_id: int,
    *,
    investigation_id: str | None,
    real_verdict: str | None,
) -> RulePriorDecision | None:
    """Put the real verdict beside the decision, and say whether they agree.

    ``real_verdict`` None means the real run reached no verdict (an error, a
    pipeline fallback). There is then nothing to compare, and the decision
    neither agrees nor disagrees.
    """
    row = await db.get(RulePriorDecision, decision_id)
    if row is None:
        return None
    row.investigation_id = investigation_id
    row.real_verdict = real_verdict
    if row.applies and real_verdict is not None and row.would_verdict is not None:
        row.agree = real_verdict == row.would_verdict
    await db.commit()
    return row


async def clear_suspension(db: AsyncSession, rule_name: str, *, by: str) -> int:
    """An analyst clears the suspension of a rule. Returns the rows cleared."""
    result = await db.execute(
        update(RulePriorDecision)
        .where(
            RulePriorDecision.rule_name == rule_name,
            RulePriorDecision.agree.is_(False),
            RulePriorDecision.cleared_at.is_(None),
        )
        .values(cleared_at=utcnow(), cleared_by=by[:80])
        .execution_options(synchronize_session=False)
    )
    await db.commit()
    return int(getattr(result, "rowcount", 0) or 0)


@dataclass(frozen=True)
class RulePriorStats:
    """One rule's rule-prior record, for the Detection tuning panel."""

    covered: int = 0
    agreements: int = 0
    disagreements: int = 0
    suspended: bool = False
    # The covered alerts and the disagreements split by safeguard 1: both
    # addresses internal, or a known external address.
    covered_internal: int = 0
    covered_known_external: int = 0
    disagreements_internal: int = 0
    disagreements_known_external: int = 0
    # Covered alerts that got no real run (live mode, not sampled).
    unchecked: int = 0
    # Why the prior held back on the newest alert it did not cover.
    last_reason: str | None = None


async def stats_by_rule(
    db: AsyncSession, rule_names: Sequence[str], *, days: int = 30
) -> dict[str, RulePriorStats]:
    """Covered alerts, agreements, disagreements and the suspension, per rule.

    The covered alerts and the disagreements are also split by the reason of
    the cover: ``covered`` (both addresses internal) and
    ``covered_known_external``.
    """
    names = [r for r in dict.fromkeys(rule_names) if r]
    if not names:
        return {}
    since = utcnow() - timedelta(days=days)

    def _count(condition: Any) -> Any:
        return func.sum(case((condition, 1), else_=0))

    applies = RulePriorDecision.applies.is_(True)
    disagree = RulePriorDecision.agree.is_(False)
    internal = RulePriorDecision.reason == COVERED
    external = RulePriorDecision.reason == COVERED_KNOWN_EXTERNAL
    counts = await db.execute(
        select(
            RulePriorDecision.rule_name,
            _count(applies),
            _count(RulePriorDecision.agree.is_(True)),
            _count(disagree),
            _count(and_(applies, RulePriorDecision.agree.is_(None))),
            _count(and_(applies, internal)),
            _count(and_(applies, external)),
            _count(and_(applies, internal, disagree)),
            _count(and_(applies, external, disagree)),
        )
        .where(RulePriorDecision.rule_name.in_(names), RulePriorDecision.created_at >= since)
        .group_by(RulePriorDecision.rule_name)
    )
    suspended = set(
        (
            await db.scalars(
                select(RulePriorDecision.rule_name).where(
                    RulePriorDecision.rule_name.in_(names),
                    RulePriorDecision.agree.is_(False),
                    RulePriorDecision.cleared_at.is_(None),
                )
            )
        ).all()
    )
    last_reason: dict[str, str] = {}
    ranked = (
        select(
            RulePriorDecision.rule_name,
            RulePriorDecision.reason,
            func.row_number()
            .over(
                partition_by=RulePriorDecision.rule_name,
                order_by=(RulePriorDecision.created_at.desc(), RulePriorDecision.id.desc()),
            )
            .label("rn"),
        )
        .where(
            RulePriorDecision.rule_name.in_(names),
            or_(RulePriorDecision.applies.is_(False), RulePriorDecision.applies.is_(None)),
        )
        .subquery()
    )
    for rule, reason in (
        await db.execute(select(ranked.c.rule_name, ranked.c.reason).where(ranked.c.rn == 1))
    ).all():
        last_reason[str(rule)] = str(reason)
    out: dict[str, RulePriorStats] = {}
    for row in counts.all():
        rule = row[0]
        covered, agreements, disagreements, unchecked, c_in, c_ext, d_in, d_ext = (
            int(v or 0) for v in row[1:]
        )
        out[str(rule)] = RulePriorStats(
            covered=covered,
            agreements=agreements,
            disagreements=disagreements,
            suspended=rule in suspended,
            unchecked=unchecked,
            last_reason=last_reason.get(str(rule)),
            covered_internal=c_in,
            covered_known_external=c_ext,
            disagreements_internal=d_in,
            disagreements_known_external=d_ext,
        )
    for rule in suspended:
        if rule not in out:
            out[rule] = RulePriorStats(suspended=True)
    return out


__all__ = [
    "COVERED",
    "COVERED_KNOWN_EXTERNAL",
    "RULE_PRIOR_CLASS",
    "RulePriorStats",
    "clear_suspension",
    "context_names",
    "hosts_have_tier2_signal",
    "in_open_campaign",
    "model_backed_runs",
    "normalize_name",
    "record_decision",
    "rule_has_analyst_override",
    "rule_is_suspended",
    "settle_decision",
    "stats_by_rule",
    "stored_external_names",
]
