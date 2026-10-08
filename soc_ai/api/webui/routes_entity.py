"""Entity pivot page (E3.5): a read-model answering "who is this and should I worry".

``GET /entity/{value}`` merges an entity's investigations (``src_ip``/``dest_ip``
match, or the host name for a name) and hunt findings (whose ``hosts[]`` names
it) into ONE time-sorted timeline, newest first. It also says what the value
is (an internal address, an external address, a host name, a user account or
a domain), how many leads and observations name it, and the first and last
time soc-ai saw it.

``GET /search/entities`` is the palette's server half. The palette searched
the investigations and alert groups it held, so a user named in a live lead,
a domain and a hunt id all answered "No matches" (dogfood 2026-10-06, 7.2 and
7.4).

Pure read-model: no new writes, no migration. The hunt-findings scan reads
report JSON in Python, so its bound is the real guardrail (see
:func:`soc_ai.store.hunts.findings_for_entity`). Analyst-readable (the blanket
``router`` auth), NOT admin-only.
"""

from __future__ import annotations

import ipaddress
import logging
from collections.abc import Iterable, Sequence
from datetime import UTC, datetime, timedelta
from typing import Any, Literal
from urllib.parse import quote

from fastapi import Depends, Query, Request
from pydantic import BaseModel
from sqlalchemy import func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from soc_ai.api.deps import get_settings_dep
from soc_ai.api.webui._errors import api_error
from soc_ai.api.webui._shared import (
    _iso_utc,
    _sev,
    _verdict,
    router,
)
from soc_ai.api.webui._timeline import EntityRefOut
from soc_ai.config import Settings
from soc_ai.store import host_machines
from soc_ai.store import hunts as hunt_svc
from soc_ai.store.models import (
    EntityObservation,
    HostDossierField,
    Hunt,
    Investigation,
    Lead,
)
from soc_ai.tools.online import is_internal_ip

_LOGGER = logging.getLogger(__name__)

# Bounds for the read-model queries. The investigation query is index-friendly
# (low-cardinality src/dst equality); the hunt-findings scan reads report JSON in
# Python, so its bound is the real guardrail (see findings_for_entity).
_INV_LIMIT = 50
_HUNT_SCAN_LIMIT = 100
# The newest leads the entity read scans for a name. Lead entities live in a
# JSON column, so the match runs in Python over a bounded set.
_LEAD_SCAN_LIMIT = 500
# The observations the entity read counts are the ones the host page lists.
_OBSERVATION_DAYS = 30
# Results per group in the palette search.
_SEARCH_CAP = 6
_SEARCH_MIN = 2

EntityType = Literal["address", "external_address", "host", "user", "domain", "name"]
_HINTS: tuple[str, ...] = ("address", "external_address", "host", "user", "domain")


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
    # Investigations with a true-positive verdict. The first line of the page
    # says this number before anything else.
    truePositiveCount: int = 0
    # Every lead that names the entity, and the ones still open: new, or under
    # a hunt. A closed lead is history; an open one waits on someone.
    leadCount: int = 0
    openLeadCount: int = 0
    # Observations on the entity in the last 30 days, from every source.
    observationCount: int = 0


class EntityOut(BaseModel):
    value: str
    # Cheap classification: parseable as an IP → "ip", else "host". "unknown" is
    # reserved for an empty/blank value the router would never route to.
    kind: Literal["ip", "host", "unknown"]
    # What the value is, in the words the page uses. An address inside the
    # internal ranges is ``address``, any other address ``external_address``.
    # A name a machine answers to is ``host``. A name a lead or an observation
    # records as an account is ``user``, and a name a machine is joined to is
    # ``domain``. Any other name is ``name``: the page knows the text and
    # nothing about what it names.
    type: EntityType = "name"
    timeline: list[EntityTimelineItem] = []
    summary: EntitySummaryOut = EntitySummaryOut()
    # The primary address of the one machine the dossier knows by this name.
    # The page sends a known name to that host's page: a name that stopped on
    # "the timeline is empty" was a dead end. Null for an address.
    host_ip: str | None = None
    # The key of the machine this address or name belongs to, for the machine
    # page (`/hosts/<key>`). Null when no machine holds it, or when a name
    # belongs to two machines.
    host_key: str | None = None
    # The first and the last time soc-ai recorded the entity: an investigation,
    # a hunt finding, a lead or an observation. Null when nothing names it.
    first_seen: str | None = None
    last_seen: str | None = None
    # For a domain: the machines joined to it. Null for any other type.
    domain_machines: int | None = None


def _classify(value: str) -> Literal["ip", "host", "unknown"]:
    """IP if it parses as an IPv4/IPv6 address, else host. Blank → unknown."""
    if not value.strip():
        return "unknown"
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return "host"
    return "ip"


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value.strip())
    except ValueError:
        return False
    return True


def _naive(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    return value.astimezone(UTC).replace(tzinfo=None) if value.tzinfo else value


async def _investigations(db: AsyncSession, value: str, *, name: bool) -> list[Investigation]:
    """Real investigations that name *value*: either end of the flow, or the
    reporting host for a name. Newest first, bounded. Synth-eval rows never
    narrate an entity's history (see ``investigations.for_entity``)."""
    match = (Investigation.src_ip == value) | (Investigation.dest_ip == value)
    if name:
        match = match | (func.lower(Investigation.host_name) == value.lower())
    rows = await db.scalars(
        select(Investigation)
        .where(match)
        .where(Investigation.is_synth_eval.is_(False))
        .order_by(Investigation.created_at.desc(), Investigation.id.desc())
        .limit(_INV_LIMIT)
    )
    return list(rows.all())


def _lead_pairs(lead: Lead) -> list[tuple[str, str]]:
    """The ``(kind, key)`` pairs one lead names, whatever shape the row holds."""
    out: list[tuple[str, str]] = []
    for entry in lead.entities_json or []:
        if isinstance(entry, (list, tuple)) and len(entry) >= 2:
            out.append((str(entry[0] or ""), str(entry[1] or "")))
        elif isinstance(entry, dict):
            out.append((str(entry.get("kind") or ""), str(entry.get("key") or "")))
    return out


async def _leads_naming(db: AsyncSession, value: str) -> list[tuple[Lead, str]]:
    """The newest leads that name *value*, each with the kind the lead records."""
    folded = value.casefold()
    rows = (
        await db.scalars(
            select(Lead).order_by(Lead.formed_at.desc(), Lead.id.desc()).limit(_LEAD_SCAN_LIMIT)
        )
    ).all()
    out: list[tuple[Lead, str]] = []
    for lead in rows:
        for kind, key in _lead_pairs(lead):
            if key.casefold() == folded:
                out.append((lead, kind))
                break
    return out


async def _observations_naming(
    db: AsyncSession, value: str, *, since: datetime
) -> tuple[int, set[str], datetime | None, datetime | None]:
    """How many observations name *value*, the kinds they record, and the
    first and last time one was written."""
    keyed = func.lower(EntityObservation.entity_key) == value.lower()
    row = (
        await db.execute(
            select(
                func.count(EntityObservation.id),
                func.min(EntityObservation.first_seen_at),
                func.max(EntityObservation.born_at),
            ).where(keyed, EntityObservation.born_at >= since)
        )
    ).one()
    kinds = set(
        (
            await db.scalars(select(EntityObservation.entity_kind).where(keyed).distinct().limit(4))
        ).all()
    )
    return int(row[0] or 0), kinds, row[1], row[2]


async def _domain_machines(db: AsyncSession, value: str) -> int:
    """The address rows joined to the domain *value*, by declaration or inference."""
    folded = value.lower()
    count = await db.scalar(
        select(func.count(func.distinct(HostDossierField.dossier_id))).where(
            HostDossierField.field == "domain_membership",
            or_(
                func.lower(HostDossierField.operator_value) == folded,
                func.lower(HostDossierField.inferred_value) == folded,
            ),
        )
    )
    return int(count or 0)


def _open(lead: Lead) -> bool:
    return lead.status in ("open", "hunting")


def _edge(stamps: Iterable[datetime | None], *, newest: bool) -> datetime | None:
    held = [s for s in (_naive(x) for x in stamps) if s is not None]
    if not held:
        return None
    return max(held) if newest else min(held)


@router.get("/entity/{value}", response_model=EntityOut)
async def get_entity(
    request: Request,
    value: str,
    type_: str | None = Query(None, alias="type", max_length=24),
    settings: Settings = Depends(get_settings_dep),
) -> EntityOut:
    """One screen of an entity's history: its investigations + hunt findings,
    merged and sorted newest-first, with the leads and observations that name
    it counted. An entity we know nothing about returns an empty timeline
    (200, not 404) — "no history" is a valid answer to look at.

    ``type`` is the caller's hint for a name: ``user`` or ``domain``. A link
    from a lead knows a user is a user, and a user that shares a name with a
    machine must not open the machine. A hint the route does not know is
    ignored.

    Synth-eval rows never reach this screen: both queries EXCLUDE them (see
    their docstrings). This page narrates a host's real history — including
    ``latestVerdict``, the box's current disposition — and a planted scenario
    describes nothing that happened on the box, so exclusion beats badging
    here. The runs stay visible (badged) on their list and detail surfaces.

    A blank value is a 400. It used to answer 200 with type "unknown" and an
    empty timeline, which reads as an entity with no history.
    """
    if not value.strip():
        raise api_error(
            400,
            "empty_entity",
            "The entity is empty. Send an IP address, a host name or a user name.",
        )
    kind = _classify(value)
    hint = (type_ or "").strip().lower()
    hint = hint if hint in _HINTS else ""
    since = datetime.now(UTC).replace(tzinfo=None) - timedelta(days=_OBSERVATION_DAYS)
    async with request.app.state.db_sessionmaker() as db:
        investigations = await _investigations(db, value, name=kind == "host")
        findings = await hunt_svc.findings_for_entity(db, value, scan_limit=_HUNT_SCAN_LIMIT)
        # A user or a domain is not a machine, whatever a machine is called.
        machine = (
            None
            if hint in ("user", "domain")
            else await host_machines.resolve_membership(db, value)
        )
        leads = await _leads_naming(db, value)
        observed, observed_kinds, obs_first, obs_last = await _observations_naming(
            db, value, since=since
        )
        domain_count = (
            await _domain_machines(db, value)
            if kind == "host" and hint in ("", "domain") and machine is None
            else 0
        )
    host_key = machine.key if machine is not None else None
    host_ip = machine.primary_ip if machine is not None and kind == "host" else None

    entity_type: EntityType
    if kind == "ip":
        entity_type = "address" if is_internal_ip(value, settings) else "external_address"
    elif hint == "user":
        entity_type = "user"
    elif hint == "domain":
        entity_type = "domain"
    elif hint == "host" or machine is not None:
        entity_type = "host"
    elif "user" in observed_kinds or any(k == "user" for _, k in leads):
        entity_type = "user"
    elif domain_count > 0:
        entity_type = "domain"
    else:
        entity_type = "name"

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

    stamps_first: list[datetime | None] = [inv.created_at for inv in investigations]
    stamps_first += [f["ts"] for f in findings]
    stamps_first += [lead.formed_at for lead, _ in leads]
    stamps_last = list(stamps_first)
    stamps_last += [lead.updated_at for lead, _ in leads]
    first_seen = _edge([*stamps_first, obs_first], newest=False)
    last_seen = _edge([*stamps_last, obs_last], newest=True)

    return EntityOut(
        value=value,
        kind=kind,
        type=entity_type,
        host_ip=host_ip,
        host_key=host_key,
        timeline=items,
        first_seen=_iso_utc(first_seen) or None,
        last_seen=_iso_utc(last_seen) or None,
        domain_machines=domain_count if entity_type == "domain" else None,
        summary=EntitySummaryOut(
            investigationCount=len(investigations),
            huntFindingCount=len(findings),
            # investigations came back newest-first.
            latestVerdict=(_verdict(investigations[0].verdict) if investigations else None),
            truePositiveCount=sum(1 for inv in investigations if inv.verdict == "true_positive"),
            leadCount=len(leads),
            openLeadCount=sum(1 for lead, _ in leads if _open(lead)),
            observationCount=observed,
        ),
    )


# ---------------------------------------------------------------------------
# Entity links: what an investigation names, and where each one opens
# ---------------------------------------------------------------------------


def _entity_href(value: str, entity_type: str, host_key: str | None) -> str:
    """The in-app path for one entity. A machine opens its page directly."""
    if host_key:
        return f"/hosts/{quote(host_key, safe='')}"
    suffix = f"?type={entity_type}" if entity_type in ("user", "domain") else ""
    return f"/entity/{quote(value, safe='')}{suffix}"


async def entity_refs(
    db: AsyncSession,
    settings: Settings,
    named: Sequence[tuple[str, str, str | None]],
) -> list[EntityRefOut]:
    """Resolve what a record names into links.

    *named* holds ``(value, role, type_hint)`` triples: ``role`` is where the
    record names the value, and ``type_hint`` is ``user``, ``domain`` or
    ``host`` when the record knows it, else ``None``. A value named twice keeps
    its first role. A blank value is skipped.
    """
    out: list[EntityRefOut] = []
    seen: set[str] = set()
    for raw, role, hint in named:
        value = (raw or "").strip()
        if not value or value == "-" or value.casefold() in seen:
            continue
        seen.add(value.casefold())
        if _is_ip(value):
            entity_type = "address" if is_internal_ip(value, settings) else "external_address"
        elif hint in ("user", "domain"):
            entity_type = hint
        else:
            entity_type = "host"
        held = (
            None
            if entity_type in ("user", "domain", "external_address")
            else await host_machines.resolve_membership(db, value)
        )
        host_key = held.key if held is not None else None
        out.append(
            EntityRefOut(
                value=value,
                type=entity_type,
                role=role,
                host_key=host_key,
                href=_entity_href(value, entity_type, host_key),
            )
        )
    return out


async def investigation_entities(
    db: AsyncSession,
    settings: Settings,
    *,
    src: str | None,
    dst: str | None,
    reporter: str | None,
    subject: dict[str, Any] | None,
) -> list[EntityRefOut]:
    """Every entity one investigation names: both ends of the flow, the
    reporting host, and the entities of the lead a promoted run came from."""
    named: list[tuple[str, str, str | None]] = [
        (src or "", "source", None),
        (dst or "", "destination", None),
        (reporter or "", "reporter", "host"),
    ]
    lead_id = (subject or {}).get("lead_id") if isinstance(subject, dict) else None
    if isinstance(lead_id, int):
        lead = await db.get(Lead, lead_id)
        if lead is not None:
            for kind, key in _lead_pairs(lead):
                named.append((key, "lead", "user" if kind == "user" else None))
    return await entity_refs(db, settings, named)


# ---------------------------------------------------------------------------
# The palette's server half
# ---------------------------------------------------------------------------


class EntitySearchHitOut(BaseModel):
    """One palette hit the client cannot find in the lists it holds.

    ``label`` is the first line and ``detail`` the second. Two hits never
    share both: the detail names the source, the type or the id.
    """

    type: Literal["user", "domain", "address", "external_address", "hunt"]
    value: str
    label: str
    detail: str
    href: str


class EntitySearchOut(BaseModel):
    q: str
    hits: list[EntitySearchHitOut]


def _hunt_detail(hunt: Hunt) -> str:
    status = {"complete": "finished", "running": "running", "error": "failed"}.get(
        hunt.status, hunt.status
    )
    return f"Hunt {hunt.id} · {status}"


@router.get("/search/entities", response_model=EntitySearchOut)
async def search_entities(
    request: Request,
    q: str = Query("", max_length=253),
    settings: Settings = Depends(get_settings_dep),
) -> EntitySearchOut:
    """Users, domains, addresses and hunts that match *q*, for the palette.

    - A user is a key a lead or an observation records as an account.
    - A domain is a value of a machine's domain membership.
    - An address is an end of an investigation's flow that no machine holds,
      or the query itself when it is a whole address that no machine holds.
    - A hunt matches on its id or its objective.

    Machines are not here: the palette asks ``GET /hosts`` for them, so the
    palette and the Hosts list give one answer. Case is ignored. A query under
    two characters answers no hits.
    """
    needle = q.strip()
    if len(needle) < _SEARCH_MIN:
        return EntitySearchOut(q=needle, hits=[])
    folded = needle.casefold()
    like = f"%{folded}%"
    hits: list[EntitySearchHitOut] = []
    async with request.app.state.db_sessionmaker() as db:
        # Users: the account keys leads and observations record.
        users: dict[str, str] = {}
        for lead in (
            await db.scalars(select(Lead).order_by(Lead.formed_at.desc()).limit(_LEAD_SCAN_LIMIT))
        ).all():
            for kind, key in _lead_pairs(lead):
                if kind == "user" and folded in key.casefold() and key.casefold() not in users:
                    users[key.casefold()] = f"{key}|Account named in lead {lead.id}"
        for key in (
            await db.scalars(
                select(EntityObservation.entity_key)
                .where(
                    EntityObservation.entity_kind == "user",
                    func.lower(EntityObservation.entity_key).like(like),
                )
                .distinct()
                .limit(_SEARCH_CAP)
            )
        ).all():
            users.setdefault(key.casefold(), f"{key}|Account with observations")
        for packed in list(users.values())[:_SEARCH_CAP]:
            key, detail = packed.split("|", 1)
            hits.append(
                EntitySearchHitOut(
                    type="user",
                    value=key,
                    label=key,
                    detail=f"User · {detail}",
                    href=_entity_href(key, "user", None),
                )
            )

        # Domains: what machines are joined to.
        domains: dict[str, str] = {}
        for op, inferred in (
            await db.execute(
                select(HostDossierField.operator_value, HostDossierField.inferred_value)
                .where(
                    HostDossierField.field == "domain_membership",
                    or_(
                        func.lower(HostDossierField.operator_value).like(like),
                        func.lower(HostDossierField.inferred_value).like(like),
                    ),
                )
                .limit(200)
            )
        ).all():
            for candidate in (op, inferred):
                text = str(candidate or "").strip()
                if text and folded in text.casefold():
                    domains.setdefault(text.casefold(), text)
        for text in list(domains.values())[:_SEARCH_CAP]:
            joined = await _domain_machines(db, text)
            hits.append(
                EntitySearchHitOut(
                    type="domain",
                    value=text,
                    label=text,
                    detail=f"Domain · {joined} address{'es' if joined != 1 else ''} joined",
                    href=_entity_href(text, "domain", None),
                )
            )

        # Addresses no machine holds: the ones investigations name.
        addresses: list[str] = []
        if _is_ip(needle):
            addresses.append(str(ipaddress.ip_address(needle)))
        for src, dst in (
            await db.execute(
                select(Investigation.src_ip, Investigation.dest_ip)
                .where(
                    or_(
                        Investigation.src_ip.like(f"{needle}%"),
                        Investigation.dest_ip.like(f"{needle}%"),
                    ),
                    Investigation.is_synth_eval.is_(False),
                )
                .order_by(Investigation.created_at.desc())
                .limit(200)
            )
        ).all():
            for ip in (src, dst):
                if ip and str(ip).startswith(needle) and ip not in addresses:
                    addresses.append(str(ip))
        shown = 0
        for ip in addresses:
            if shown >= _SEARCH_CAP:
                break
            if await host_machines.resolve_membership(db, ip) is not None:
                continue
            internal = is_internal_ip(ip, settings)
            hits.append(
                EntitySearchHitOut(
                    type="address" if internal else "external_address",
                    value=ip,
                    label=ip,
                    detail=(
                        "Internal address · no machine holds it"
                        if internal
                        else "External address · outside the internal ranges"
                    ),
                    href=_entity_href(ip, "address", None),
                )
            )
            shown += 1

        # Hunts: the id, whole or in part, or the objective.
        for hunt in (
            await db.scalars(
                select(Hunt)
                .where(
                    or_(
                        func.lower(Hunt.id).like(like),
                        func.lower(Hunt.objective).like(like),
                    ),
                    Hunt.is_synth_eval.is_(False),
                )
                .order_by(Hunt.created_at.desc())
                .limit(_SEARCH_CAP)
            )
        ).all():
            objective = " ".join((hunt.objective or "").split())
            hits.append(
                EntitySearchHitOut(
                    type="hunt",
                    value=hunt.id,
                    label=objective or hunt.id,
                    detail=_hunt_detail(hunt),
                    href=f"/hunts/{quote(hunt.id, safe='')}",
                )
            )
    return EntitySearchOut(q=needle, hits=hits)


__all__ = [
    "EntityOut",
    "EntitySearchOut",
    "entity_refs",
    "get_entity",
    "investigation_entities",
    "search_entities",
]
