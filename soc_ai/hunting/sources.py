"""Observations from every source.

The observations table held profile departures only. A catalog hit was a hunt
row. A triaged alert was an alert. Three tables cannot form one lead. These
three adapters write through :func:`soc_ai.hunting.leads.record_observation`,
so fingerprints, refresh on repeat and stacking behave the same for all
sources. Each adapter then calls :func:`form_leads` for the entities it
touched.
"""

from __future__ import annotations

import ipaddress
from collections.abc import Iterable, Sequence
from datetime import datetime
from typing import Any

from sqlalchemy import delete
from sqlalchemy.ext.asyncio import AsyncSession

from soc_ai.hunting.execute import Candidate
from soc_ai.hunting.leads import LeadOutcome, content_fingerprint, form_leads, record_observation
from soc_ai.hunting.spec import HuntSpec
from soc_ai.hunting.weight import Kind, alert_weight
from soc_ai.store.hunt_spec_state import GAP_SCOPE
from soc_ai.store.models import EntityObservation

__all__ = [
    "ALERT_SPEC_ID",
    "HUNT_SPEC_ID",
    "internal_hosts",
    "observe_alert_verdict",
    "observe_catalog_hits",
    "observe_hunt_finding",
]

# The spec_id an alert or a hunt finding is recorded under. Neither is an
# analytic in the catalog. The fingerprint carries the identity.
ALERT_SPEC_ID = "alert"
HUNT_SPEC_ID = "hunt"

_SCOPE_TO_ENTITY = {"host": "host", "ip": "host", "user": "user"}

# Python reports the IETF documentation and benchmarking ranges as private, so
# ``is_private`` alone lets 198.51.100.7 and 203.0.113.9 into an estate. No
# deployment numbers its hosts out of them. They appear in fixtures, in the
# leak gate's substitutions and in this project's own tests, which is exactly
# the traffic that must not become an observation about a host.
_NOT_AN_ESTATE = (
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
    ipaddress.ip_network("198.18.0.0/15"),
    ipaddress.ip_network("2001:db8::/32"),
)


def internal_hosts(values: Iterable[str | None]) -> list[str]:
    """The private unicast addresses in *values*, in order, without repeats.

    The dossier sweep purges observations outside the configured estate later.
    This function needs no settings, so the store can call it.
    """
    out: list[str] = []
    for value in values:
        text = str(value or "").strip()
        if not text or text in out:
            continue
        try:
            addr = ipaddress.ip_address(text)
        except ValueError:
            continue
        if any(addr in net for net in _NOT_AN_ESTATE if addr.version == net.version):
            continue
        if addr.is_private and not (
            addr.is_loopback or addr.is_multicast or addr.is_link_local or addr.is_unspecified
        ):
            out.append(text)
    return out


async def observe_catalog_hits(
    db: AsyncSession,
    *,
    spec: HuntSpec,
    candidates: Sequence[Candidate],
    now: datetime,
    shadow: bool = False,
    receipts: dict[str, dict[str, Any]] | None = None,
) -> LeadOutcome:
    """Record one observation per fresh candidate and form leads.

    A gap candidate is a coverage record. It is never an observation. The kind
    comes from the analytic: a no-baseline analytic writes a finding-grade
    observation, any other analytic writes ``catalog_match``.

    The evidence carries the hosts the candidate's own documents named, under
    ``related``. A hit scoped on an account is about a machine as well, and
    without that pair the account's lead and the machine's lead are two leads
    about one event. A lateral-movement hit scoped on a host names the other
    end the same way.

    ``receipts`` is keyed by scope key and carries the receipts packet of a
    shadow hit. The app shows a hit without complete receipts as "could not
    run" and names the missing part.
    """
    kind = Kind.PRIOR_NO_BASELINE if spec.no_benign_baseline else Kind.CATALOG_MATCH
    # ``scope_kind`` is a Literal with no empty member, so the old
    # ``or "host"`` could never run. The fallback that does the work is the
    # lookup's own default: a scope kind this table does not name is recorded
    # against a host.
    entity_kind = _SCOPE_TO_ENTITY.get(spec.scope_kind, "host")
    touched: set[tuple[str, str]] = set()
    for candidate in candidates:
        if candidate.scope_key == GAP_SCOPE or not candidate.scope_key:
            continue
        # ``Candidate.hosts`` already excludes the scope key, so a host-scoped
        # candidate names only the other end.
        related = [["host", host] for host in candidate.hosts]
        await record_observation(
            db,
            entity_kind=entity_kind,
            entity_key=candidate.scope_key,
            kind=kind,
            spec_id=spec.id,
            fingerprint=content_fingerprint(spec.id, candidate.scope_key),
            summary=(
                f"{spec.title}: {candidate.scope_key} "
                f"({candidate.doc_count} document{'' if candidate.doc_count == 1 else 's'})"
            ),
            evidence={
                "sample_ids": list(candidate.sample_ids),
                "anchor_id": candidate.anchor_id,
                "anchor_index": candidate.anchor_index,
                "first_seen": candidate.first_seen,
                "last_seen": candidate.last_seen,
                **({"related": related} if related else {}),
                **(
                    {"receipts": receipts[candidate.scope_key]}
                    if receipts and candidate.scope_key in receipts
                    else {}
                ),
            },
            now=now,
            # The source is the adapter, not the status. A shadow hit is a
            # catalog hit that is marked shadow, and writing "candidate" here
            # made the two facts one field that could only say one of them.
            source="catalog",
            shadow=shadow,
        )
        touched.add((entity_kind, candidate.scope_key))
    if not touched:
        return LeadOutcome()
    return await form_leads(db, entity_keys=sorted(touched), now=now)


async def observe_alert_verdict(
    db: AsyncSession,
    *,
    alert_id: str,
    rule_name: str | None,
    verdict: str | None,
    confidence: float | None,
    hosts: Sequence[str | None],
    now: datetime,
) -> LeadOutcome:
    """Record a triaged alert on its internal hosts, weighted by verdict.

    A false positive is not recorded. A verdict changed to false positive
    deletes the observation. The alert id is the fingerprint, so a new verdict
    refreshes the row.
    """
    weight = alert_weight(verdict)
    entities = internal_hosts(hosts)
    if weight is None:
        await db.execute(
            delete(EntityObservation).where(
                EntityObservation.spec_id == ALERT_SPEC_ID,
                EntityObservation.fingerprint == alert_id,
            )
        )
        await db.commit()
        return LeadOutcome()
    if not entities:
        return LeadOutcome()
    label = str(verdict or "").replace("_", " ")
    conf = f" at {confidence:.2f}" if isinstance(confidence, (int, float)) else ""
    for host in entities:
        await record_observation(
            db,
            entity_kind="host",
            entity_key=host,
            kind=Kind.ALERT,
            spec_id=ALERT_SPEC_ID,
            fingerprint=alert_id,
            summary=f"{rule_name or 'alert'}: {label}{conf}",
            evidence={
                "alert_id": alert_id,
                "verdict": verdict,
                "confidence": confidence,
                "rule_name": rule_name,
            },
            now=now,
            source="alert",
            weight=weight,
        )
    return await form_leads(db, entity_keys=[("host", h) for h in entities], now=now)


async def observe_hunt_finding(
    db: AsyncSession,
    *,
    hunt_id: str,
    ordinal: int,
    finding: dict[str, Any],
    now: datetime,
) -> LeadOutcome:
    """Record a promoted hunt finding on each internal host it names."""
    entities = internal_hosts(finding.get("hosts") or [])
    if not entities:
        return LeadOutcome()
    title = str(finding.get("title") or "Hunt finding")
    for host in entities:
        await record_observation(
            db,
            entity_kind="host",
            entity_key=host,
            kind=Kind.HUNT_FINDING,
            spec_id=HUNT_SPEC_ID,
            fingerprint=content_fingerprint(hunt_id, ordinal),
            summary=title,
            evidence={
                "hunt_id": hunt_id,
                "ordinal": ordinal,
                "citations": list(finding.get("citations") or []),
            },
            now=now,
            source="hunt",
        )
    return await form_leads(db, entity_keys=[("host", h) for h in entities], now=now)
