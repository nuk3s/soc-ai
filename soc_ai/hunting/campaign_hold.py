"""The rule that a hunt finding restates a campaign (recommendation 7, H5).

Prod, 2026-11-14: the scheduled hunt reported again a file read that a
campaign already held, and soc-ai investigated it again. A finding that
restates a campaign now gets no investigation of its own. Its entry on the
hunt reads the state ``campaign`` and names the campaign
(:data:`soc_ai.store.hunts.LINK_CAMPAIGN`).

The rule is strict on purpose. A hunt must never report too little because of
a campaign block, so every doubt goes to "investigate". A threat finding is
held by a campaign only when ALL of these hold (:func:`held_by`):

- Each host that it names is a machine of ONE active campaign, and the hunt
  read the block of that campaign. A cited address counts as a named host.
- It names two machines or more, or the campaign has one target.
- It cites one document or more. Each one resolves to a document that the
  hunt stored, with a time that is not after the last event of the campaign.
- Its stage is stated and is not above the stage that the campaign reached.

A finding that names a user or a domain, a citation that is no stored
document, and a document with no time all fail the rule. The phase of the
hunt does not apply the rule to a lead hunt or to an evaluation hunt
(:func:`soc_ai.webui.hunt_findings.investigate_findings`).
"""

from __future__ import annotations

import ipaddress
import logging
from collections.abc import Collection, Iterable, Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from sqlalchemy import select

from soc_ai.campaigns.types import ROLE_TARGET, STAGES
from soc_ai.hunting.finding_match import StoredDocument, cited_ids
from soc_ai.hunting.findings import finding_category, finding_entities, is_run_failure_finding
from soc_ai.store.models import Campaign, CampaignParty

__all__ = [
    "HELD_REASON",
    "HoldCampaign",
    "HoldParty",
    "active_campaigns",
    "held_by",
    "machine_keys",
]

_LOGGER = logging.getLogger(__name__)

_STATUS_ACTIVE = "active"
_HOST_KINDS = frozenset({"host", "address"})

# The reason of the entry of a held finding, in words.
HELD_REASON = "The campaign holds this activity: no later stage, no new machine and no later event."


@dataclass(frozen=True)
class HoldParty:
    """One machine of a campaign: its key, its role, its name and its addresses."""

    key: str
    role: str
    name: str | None = None
    addresses: tuple[str, ...] = ()


@dataclass(frozen=True)
class HoldCampaign:
    """What the rule reads of one active campaign."""

    id: int
    title: str
    stage: str | None
    last_event: datetime
    parties: tuple[HoldParty, ...] = ()

    @property
    def targets(self) -> int:
        return sum(1 for p in self.parties if p.role == ROLE_TARGET)


def _fold(value: Any) -> str:
    return str(value or "").strip().rstrip(".").casefold()


def _rank(stage: Any) -> int:
    return STAGES.index(stage) if isinstance(stage, str) and stage in STAGES else -1


def _address(citation: str) -> str | None:
    """The address that a citation names, with or without a port, or None."""
    text = citation.strip()
    for candidate in (text, text.rsplit(":", 1)[0], text.strip("[]")):
        try:
            return str(ipaddress.ip_address(candidate.strip("[]")))
        except ValueError:
            continue
    return None


def _cited_addresses(finding: Mapping[str, Any]) -> list[str]:
    """The addresses that the citations of a finding name, folded. An address is no document."""
    raw = finding.get("citations")
    out: list[str] = []
    for citation in raw if isinstance(raw, list) else []:
        if isinstance(citation, str) and (address := _address(citation)) is not None:
            out.append(_fold(address))
    return out


def _named(finding: Mapping[str, Any]) -> list[str] | None:
    """The hosts and addresses that a finding names, or None when it names anything else."""
    values: list[str] = []
    for kind, value in finding_entities(finding):
        if kind not in _HOST_KINDS:
            return None
        values.append(_fold(value))
    return [v for v in dict.fromkeys(values) if v]


def _parties_of(
    value: str, campaigns: Sequence[HoldCampaign], machines: Mapping[str, str]
) -> dict[int, str]:
    """The campaigns where ``value`` is a machine, with the key of that machine."""
    key = machines.get(value)
    out: dict[int, str] = {}
    for campaign in campaigns:
        for party in campaign.parties:
            names = {_fold(party.name), _fold(party.key), *(_fold(a) for a in party.addresses)}
            if value in names or (key is not None and key == party.key):
                out[campaign.id] = party.key
                break
    return out


def held_by(
    finding: Mapping[str, Any],
    *,
    campaigns: Sequence[HoldCampaign],
    read: Collection[int],
    documents: Mapping[str, StoredDocument],
    machines: Mapping[str, str] | None = None,
) -> HoldCampaign | None:
    """The campaign that holds ``finding``, or None. Pure. Every doubt gives None.

    ``campaigns`` are the active campaigns, and ``read`` the ids of the ones
    whose block the hunt read. ``documents`` maps a cited id to the document
    the hunt stored (:func:`soc_ai.hunting.finding_match.stored_documents`).
    ``machines`` maps a folded host value to its machine key in the Hosts
    data (:func:`machine_keys`).
    """
    if finding_category(finding) != "threat" or is_run_failure_finding(finding):
        return None
    hosts = _named(finding)
    if not hosts:
        return None
    hosts.extend(_cited_addresses(finding))
    docs = [c for c in cited_ids(finding) if _address(c) is None]
    if not docs:
        return None
    resolved = [documents.get(d) for d in docs]
    if any(doc is None or doc.at is None for doc in resolved):
        return None
    keys = machines or {}
    shared: set[int] | None = None
    held_keys: dict[int, set[str]] = {}
    for value in dict.fromkeys(hosts):
        found = _parties_of(value, campaigns, keys)
        shared = set(found) if shared is None else shared & set(found)
        for cid, key in found.items():
            held_keys.setdefault(cid, set()).add(key)
        if not shared:
            return None
    if shared is None or len(shared) != 1:
        return None
    (campaign_id,) = shared
    campaign = next(c for c in campaigns if c.id == campaign_id)
    if campaign.id not in set(read):
        return None
    if len(held_keys[campaign.id]) < 2 and campaign.targets != 1:
        return None
    if any(doc.at > campaign.last_event for doc in resolved if doc is not None and doc.at):
        return None
    stage = finding.get("stage")
    if _rank(stage) < 0 or _rank(campaign.stage) < 0 or _rank(stage) > _rank(campaign.stage):
        return None
    return campaign


# ── the reads ───────────────────────────────────────────────────────────────


async def active_campaigns(db: Any) -> list[HoldCampaign]:
    """Every active campaign with its machines. The rule needs all of them for its ONE test."""
    rows = list((await db.scalars(select(Campaign).where(Campaign.status == _STATUS_ACTIVE))).all())
    if not rows:
        return []
    parties: dict[int, list[HoldParty]] = {}
    found = await db.scalars(
        select(CampaignParty).where(CampaignParty.campaign_id.in_([r.id for r in rows]))
    )
    for party in found.all():
        addresses = party.addresses if isinstance(party.addresses, list) else []
        parties.setdefault(int(party.campaign_id), []).append(
            HoldParty(
                key=str(party.machine_key),
                role=str(party.role),
                name=party.name or None,
                addresses=tuple(str(a) for a in addresses if a),
            )
        )
    return [
        HoldCampaign(
            id=int(row.id),
            title=str(row.title),
            stage=row.stage,
            last_event=row.last_event,
            parties=tuple(parties.get(int(row.id), [])),
        )
        for row in rows
    ]


async def machine_keys(db: Any, findings: Iterable[Mapping[str, Any]]) -> dict[str, str]:
    """The machine key of each host and cited address of ``findings``, from the Hosts data.

    A value that names no machine, or two, has no entry and stands for
    itself. Never raises: a read that fails gives no entry.
    """
    from soc_ai.store import host_machines  # noqa: PLC0415 - keeps the import graph light

    values: set[str] = set()
    for finding in findings:
        values.update(_fold(v) for k, v in finding_entities(finding) if k in _HOST_KINDS)
        values.update(_cited_addresses(finding))
    out: dict[str, str] = {}
    for value in sorted(v for v in values if v):
        try:
            membership = await host_machines.resolve_membership(db, value)
        except Exception:
            _LOGGER.warning("campaign hold: the machine of a host did not load", exc_info=True)
            continue
        if membership is not None:
            out[value] = str(membership.key)
    return out
