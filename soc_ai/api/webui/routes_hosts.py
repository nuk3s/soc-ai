"""Machine endpoints: the Hosts list with one row per device.

The dossier routes (``routes_dossier``) answer per IP address. These answer per
machine: the set of addresses the sweep holds to be one device
(:mod:`soc_ai.store.host_machines`). Production had 14 rows for one proxy on
the address list; here it is one row with its addresses under it.

The list is built in Python over the whole estate, then filtered, sorted and
paged. The estate is under 5,000 machines, and an address sort has to be
numeric, which SQL text order is not. The summary is built from the SAME rows
with the same predicates, so each count equals the ``total`` of the list call
with the matching filter. That is a test, not a hope.

The role, the declared name and the flags are read live from the address
dossiers. A declaration the operator makes between two sweeps shows at once.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any, Literal
from urllib.parse import quote

from fastapi import Depends, Query, Request
from pydantic import BaseModel, Field
from sqlalchemy import or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from soc_ai.api.deps import get_settings_dep
from soc_ai.api.webui._errors import api_error
from soc_ai.api.webui._shared import _iso_utc, router
from soc_ai.api.webui.routes_dossier import DossierOut, _current_dossier
from soc_ai.config import Settings
from soc_ai.dossier.infer import ROLE_VOCABULARY
from soc_ai.dossier.resolve import (
    DEFAULT_MIN_CONFIDENCE,
    DEFAULT_STALENESS_HOURS,
    resolve_field,
)
from soc_ai.store import host_dossier as dossier_store
from soc_ai.store import host_machines
from soc_ai.store.host_machines import address_sort_key, normalize_mac, short_name
from soc_ai.store.models import DossierRun, HostDossier, HostDossierField, HostMachine

# "New" means first seen inside this window.
_NEW_DAYS = 7
# Rows on one page of the list.
_DEFAULT_LIMIT = 50
_MAX_LIMIT = 500
# Addresses a list row carries. The machine page lists all of them.
_ROW_ADDRESSES = 5

_SORTS: tuple[str, ...] = ("name", "address", "role", "agent", "events", "first_seen", "last_seen")
_DIRS: tuple[str, ...] = ("asc", "desc")
# The direction a column sorts in when the request names none: text and
# addresses A to Z, counts and times largest and newest first.
_DEFAULT_DIR: dict[str, str] = {
    "name": "asc",
    "address": "asc",
    "role": "asc",
    "agent": "asc",
    "events": "desc",
    "first_seen": "desc",
    "last_seen": "desc",
}
_ROLE_BUCKETS: tuple[str, ...] = ("unknown", "low_confidence", "stale")
_YES_NO: tuple[str, ...] = ("yes", "no")
_ACTIVITY: tuple[str, ...] = ("active", "all")
_SEEN: tuple[str, ...] = ("new",)
_HEALTH: tuple[str, ...] = ("broken", "attention")

RoleState = Literal["declared", "inferred", "low_confidence", "stale", "unknown"]
_AsMatched = Literal["address", "name", "mac", "agent"]
_KEY_MATCH: dict[str, _AsMatched] = {"agent": "agent", "mac": "mac", "ip": "address"}

# An address prefix: digits and dots, or hex digits and colons with a colon.
_V4_PREFIX = re.compile(r"^[0-9.]+$")
_V6_PREFIX = re.compile(r"^[0-9a-f:]+$")
_MAC_TEXT = re.compile(r"^[0-9a-f:.\-]+$")


# ---------------------------------------------------------------------------
# Response models
# ---------------------------------------------------------------------------


class MachineNameOut(BaseModel):
    value: str
    source: str


class MachineAgentOut(BaseModel):
    id: str
    name: str
    os: str | None = None
    last_report: str | None = None


class MachineRoleOut(BaseModel):
    """The role of the primary address, with the state that explains it."""

    value: str | None = None
    label: str | None = None
    confidence: float | None = None
    state: RoleState = "unknown"
    # The withheld inferred role, when the state is low_confidence or stale.
    guess: str | None = None
    # Hours since the last build that evaluated the role, for a stale state.
    stale_hours: float | None = None


class MachineFlagsOut(BaseModel):
    declared: bool = False
    conflict: bool = False
    broken: bool = False
    new: bool = False
    rebound: bool = False


class MachineRowOut(BaseModel):
    """One machine in the Hosts list."""

    key: str
    href: str
    name: str | None = None
    name_source: str | None = None
    names: list[MachineNameOut] = Field(default_factory=list)
    primary_ip: str
    address_count: int = 0
    addresses: list[str] = Field(default_factory=list)
    container_count: int = 0
    agent: MachineAgentOut | None = None
    role: MachineRoleOut = Field(default_factory=MachineRoleOut)
    events: int = 0
    first_seen: str | None = None
    last_seen: str | None = None
    flags: MachineFlagsOut = Field(default_factory=MachineFlagsOut)


class MachineListOut(BaseModel):
    rows: list[MachineRowOut]
    total: int
    limit: int
    offset: int
    sort: str
    dir: str


class MachineSummaryOut(BaseModel):
    """The cards above the list. Each count is the total of one list filter."""

    machines: int = 0
    addresses: int = 0
    with_agent: int = 0
    without_agent: int = 0
    new_7d: int = 0
    named: int = 0
    unnamed: int = 0
    roles: dict[str, int] = Field(default_factory=dict)
    needs_attention: int = 0
    conflicts: int = 0
    never_built: int = 0
    last_sweep_at: str | None = None
    stale_hours: float | None = None


class MachineResolveOut(BaseModel):
    key: str
    primary_ip: str
    matched: _AsMatched


class MachineAddressOut(BaseModel):
    ip: str
    kind: str
    primary: bool = False
    first_seen: str | None = None
    last_seen: str | None = None
    events: int = 0


class MachineContainerOut(BaseModel):
    ip: str
    first_seen: str | None = None
    last_seen: str | None = None
    events: int = 0


class MachineDetailOut(MachineRowOut):
    """One machine: every address, its containers, its MACs and the primary dossier."""

    addresses: list[MachineAddressOut] = Field(default_factory=list)  # type: ignore[assignment]
    containers: list[MachineContainerOut] = Field(default_factory=list)
    macs: list[str] = Field(default_factory=list)
    merged_from: list[str] = Field(default_factory=list)
    dossier: DossierOut | None = None


# ---------------------------------------------------------------------------
# The estate view: one machine, read live
# ---------------------------------------------------------------------------


@dataclass
class _Address:
    ip: str
    kind: str
    events: int
    first_seen: datetime | None
    last_seen: datetime | None


@dataclass
class _View:
    """One machine as the list, the summary and the detail all see it."""

    row: HostMachine
    members: list[_Address]
    containers: list[_Address]
    name: str | None
    name_source: str | None
    names: list[tuple[str, str]]
    role: MachineRoleOut
    events: int
    first_seen: datetime | None
    last_seen: datetime | None
    declared: bool
    conflict: bool
    broken: bool
    build_stale: bool
    new: bool
    rebound: bool
    search_rank: int | None = field(default=None)

    @property
    def primary_ip(self) -> str:
        return self.row.primary_ip or (self.members[0].ip if self.members else "")

    @property
    def needs_attention(self) -> bool:
        return self.broken or self.build_stale


@dataclass
class _Knobs:
    now: datetime
    min_confidence: float
    staleness_hours: int
    min_observations: int


def _knobs(settings: Settings) -> _Knobs:
    return _Knobs(
        now=datetime.now(UTC),
        min_confidence=float(getattr(settings, "dossier_min_confidence", DEFAULT_MIN_CONFIDENCE)),
        staleness_hours=int(getattr(settings, "dossier_staleness_hours", DEFAULT_STALENESS_HOURS)),
        min_observations=int(
            getattr(
                settings,
                "dossier_conflict_min_observations",
                dossier_store.DEFAULT_CONFLICT_MIN_OBSERVATIONS,
            )
        ),
    )


def _naive(value: datetime) -> datetime:
    return value.astimezone(UTC).replace(tzinfo=None) if value.tzinfo else value


def _ts(value: datetime | None) -> str | None:
    return _iso_utc(value) or None


def _role(row: HostDossierField | None, knobs: _Knobs) -> MachineRoleOut:
    """The role state of one role row, as the resolver sees it."""
    if row is None:
        return MachineRoleOut()
    resolved = resolve_field(
        row,
        now=knobs.now,
        min_confidence=knobs.min_confidence,
        staleness_hours=knobs.staleness_hours,
    )
    value = (resolved.value or "").strip()
    if resolved.overridden and value and value.lower() != "unknown":
        return MachineRoleOut(value=value, label=_label(value), confidence=1.0, state="declared")
    if resolved.inference_assertable and value and value.lower() != "unknown":
        return MachineRoleOut(
            value=value, label=_label(value), confidence=resolved.confidence, state="inferred"
        )
    guess = (row.inferred_value or "").strip()
    if not guess or guess.lower() == "unknown" or resolved.overridden:
        return MachineRoleOut()
    if resolved.inference_reason == "stale":
        stamp = row.inferred_last_run_at
        hours = (
            round((_naive(knobs.now) - stamp).total_seconds() / 3600.0, 1)
            if stamp is not None
            else None
        )
        return MachineRoleOut(state="stale", guess=guess, stale_hours=hours)
    if resolved.inference_reason == "low_confidence":
        return MachineRoleOut(
            state="low_confidence", guess=guess, confidence=row.inferred_confidence
        )
    return MachineRoleOut()


def _label(value: str) -> str:
    return value.replace("_", " ")


def _names(
    row: HostMachine, declared: list[str]
) -> tuple[str | None, str | None, list[tuple[str, str]]]:
    """The machine's names with the live declarations first.

    The sweep wrote the names as they stood then. A declaration made or removed
    since shows now: the stored declared names are replaced by the live ones.
    """
    stored = [
        (str(entry.get("value")), str(entry.get("source") or "other"))
        for entry in (row.names_json or [])
        if isinstance(entry, dict) and entry.get("value")
    ]
    names: list[tuple[str, str]] = [(value, "declared") for value in declared]
    seen = {value.casefold() for value in declared}
    for value, source in stored:
        if source == "declared" or value.casefold() in seen:
            continue
        seen.add(value.casefold())
        names.append((value, source))
    if row.agent_name and row.agent_name.casefold() not in seen:
        names.insert(len(declared), (row.agent_name, "agent"))
    if not names:
        return None, None, []
    return names[0][0], names[0][1], names


async def _estate(db: AsyncSession, knobs: _Knobs) -> list[_View]:
    """Every live machine, read with its addresses and the live dossier facts."""
    machines = (await db.scalars(select(HostMachine).where(HostMachine.address_count > 0))).all()
    hosts = (await db.scalars(select(HostDossier).where(HostDossier.machine_id.is_not(None)))).all()
    by_machine: dict[int, list[HostDossier]] = {}
    for host in hosts:
        by_machine.setdefault(int(host.machine_id or 0), []).append(host)
    host_by_ip = {host.ip: host for host in hosts}
    primary_ids = [
        host_by_ip[m.primary_ip].id for m in machines if m.primary_ip and m.primary_ip in host_by_ip
    ]
    roles = {
        row.dossier_id: row
        for row in (
            await db.scalars(
                select(HostDossierField).where(
                    HostDossierField.field == dossier_store.ROLE_FIELD,
                    HostDossierField.dossier_id.in_(primary_ids),
                )
            )
        ).all()
    }
    declared_ids = set(
        (
            await db.scalars(
                select(HostDossierField.dossier_id).where(
                    or_(
                        HostDossierField.operator_value.is_not(None),
                        HostDossierField.operator_value_json.is_not(None),
                    )
                )
            )
        ).all()
    )
    declared_names: dict[int, str] = {
        int(dossier_id): str(value).strip()
        for dossier_id, value in (
            await db.execute(
                select(HostDossierField.dossier_id, HostDossierField.operator_value).where(
                    HostDossierField.field == dossier_store.HOSTNAME_FIELD,
                    HostDossierField.operator_value.is_not(None),
                )
            )
        ).all()
        if isinstance(value, str) and value.strip()
    }
    conflict_ids = set(
        (
            await db.scalars(
                select(HostDossierField.dossier_id).where(
                    *dossier_store._conflict_due_conditions(
                        _naive(knobs.now), knobs.min_observations
                    )
                )
            )
        ).all()
    )
    fresh_since = _naive(knobs.now) - timedelta(hours=knobs.staleness_hours)
    new_since = _naive(knobs.now) - timedelta(days=_NEW_DAYS)
    out: list[_View] = []
    for machine in machines:
        rows = by_machine.get(machine.id, [])
        members = sorted(
            (_as_address(h) for h in rows if h.address_kind != "container"),
            key=lambda a: (a.ip != machine.primary_ip, address_sort_key(a.ip)),
        )
        if not members:
            continue
        containers = sorted(
            (_as_address(h) for h in rows if h.address_kind == "container"),
            key=lambda a: address_sort_key(a.ip),
        )
        primary = host_by_ip.get(machine.primary_ip or "")
        member_ids = [h.id for h in rows if h.address_kind != "container"]
        ordered_ids = ([primary.id] if primary is not None else []) + [
            i for i in member_ids if primary is None or i != primary.id
        ]
        declared = list(
            dict.fromkeys(declared_names[i] for i in ordered_ids if i in declared_names)
        )
        name, name_source, names = _names(machine, declared)
        # The machine row keeps the first sighting of its history and of any
        # machine merged into it, so a merged machine is not "new".
        firsts = [a.first_seen for a in members if a.first_seen is not None]
        if machine.first_seen is not None:
            firsts.append(machine.first_seen)
        lasts = [a.last_seen for a in members if a.last_seen is not None]
        first_seen = min(firsts) if firsts else None
        out.append(
            _View(
                row=machine,
                members=members,
                containers=containers,
                name=name,
                name_source=name_source,
                names=names,
                role=_role(roles.get(primary.id) if primary is not None else None, knobs),
                # The machine row holds the network's events over the members
                # plus the agent's own documents once. The address rows hold
                # the network figure only, so their sum undercounts an agent
                # host. The row wins when the sweep wrote it.
                events=max(int(machine.event_count or 0), sum(a.events for a in members)),
                first_seen=first_seen,
                last_seen=max(lasts) if lasts else machine.last_seen,
                declared=any(i in declared_ids for i in member_ids),
                conflict=any(i in conflict_ids for i in member_ids),
                broken=primary is None
                or primary.last_built_at is None
                or primary.build_error is not None,
                build_stale=primary is not None
                and primary.build_error is None
                and primary.last_built_at is not None
                and primary.last_built_at < fresh_since,
                new=first_seen is not None and first_seen >= new_since,
                # The tripwire warns that an override may no longer apply, so
                # it shows only on a primary address that holds a declaration.
                rebound=primary is not None
                and primary.identity_rebound_at is not None
                and primary.id in declared_ids,
            )
        )
    return out


def _as_address(host: HostDossier) -> _Address:
    return _Address(
        ip=host.ip,
        kind=host.address_kind or "network",
        events=int(host.event_count or 0),
        first_seen=host.first_seen,
        last_seen=host.last_seen,
    )


# ---------------------------------------------------------------------------
# Search, filters, sort
# ---------------------------------------------------------------------------


def _text_rank(value: str | None, needle: str) -> int | None:
    """0 for an exact match, 1 for a prefix, 2 for a substring, case ignored."""
    if not value:
        return None
    folded = value.casefold()
    if folded == needle:
        return 0
    if folded.startswith(needle):
        return 1
    if needle in folded:
        return 2
    return None


def _search_rank(view: _View, q: str) -> int | None:
    """The match tier of one machine for the search box, or ``None``.

    Tier 0: a name or an address equals the query. Tier 1: a name or an
    address starts with it. Tier 2: any other match. Names from every source
    and the agent name match exactly, by prefix or as a substring. An address
    matches exactly or by prefix and never in the middle: "8.1" must not find
    192.0.8.123's neighbours. A MAC is an address too and matches exactly or by
    prefix in any written form. The OS and the role describe a machine and
    never name it, so a match there is tier 2 whatever its shape.
    """
    needle = q.strip().casefold()
    if not needle:
        return 0
    ranks: list[int] = []
    addresses = [a.ip for a in (*view.members, *view.containers)]
    try:
        exact = str(ipaddress.ip_address(needle))
    except ValueError:
        exact = None
    if exact is not None and exact in addresses:
        return 0
    is_prefix = bool(_V4_PREFIX.match(needle) or (":" in needle and _V6_PREFIX.match(needle)))
    if is_prefix and any(ip.casefold().startswith(needle) for ip in addresses):
        ranks.append(1)
    texts = [value for value, _ in view.names]
    if view.row.agent_name:
        texts.append(view.row.agent_name)
    for text in texts:
        rank = _text_rank(text, needle)
        if rank is not None:
            ranks.append(rank)
    for described in (view.row.os, view.role.value, view.role.label, view.role.guess):
        if _text_rank(described, needle) is not None:
            ranks.append(2)
    if "." in needle and exact is None and not _V4_PREFIX.match(needle):
        # "depot.example.test" finds the machine whose agent calls it "depot".
        label = short_name(needle)
        if label and any(value.casefold() == label for value in texts):
            ranks.append(1)
    if _MAC_TEXT.match(needle):
        digits = re.sub(r"[^0-9a-f]", "", needle)
        if len(digits) >= 4:
            for mac in view.row.macs_json or []:
                held = re.sub(r"[^0-9a-f]", "", str(mac).casefold())
                if held == digits:
                    ranks.append(0)
                elif held.startswith(digits):
                    ranks.append(1)
    return min(ranks) if ranks else None


@dataclass
class _Filters:
    q: str | None = None
    role: str | None = None
    agent: str | None = None
    activity: str = "active"
    seen: str | None = None
    declared: str | None = None
    named: str | None = None
    health: str | None = None
    conflict: str | None = None


def _role_matches(view: _View, role: str) -> bool:
    if role in _ROLE_BUCKETS:
        return view.role.state == role
    return view.role.state in ("declared", "inferred") and (view.role.value or "").lower() == role


def _yes(value: str | None, actual: bool) -> bool:
    return value is None or (value == "yes") == actual


def _keep(view: _View, filters: _Filters) -> bool:
    """Every filter but the search box. One predicate per summary count."""
    if filters.role is not None and not _role_matches(view, filters.role):
        return False
    if not _yes(filters.agent, view.row.agent_id is not None):
        return False
    if filters.seen == "new" and not view.new:
        return False
    if not _yes(filters.declared, view.declared):
        return False
    if not _yes(filters.named, view.name is not None):
        return False
    if filters.health == "broken" and not view.broken:
        return False
    if filters.health == "attention" and not view.needs_attention:
        return False
    if not _yes(filters.conflict, view.conflict):
        return False
    # The search box ignores the activity filter: a machine an analyst names
    # must be found whether or not it talked this window.
    return not (filters.activity == "active" and not filters.q and view.events <= 0)


def _sort_value(view: _View, sort: str) -> Any:
    if sort == "name":
        return view.name.casefold() if view.name else None
    if sort == "address":
        return address_sort_key(view.primary_ip) if view.primary_ip else None
    if sort == "role":
        shown = view.role.value or view.role.guess
        return shown.casefold() if shown else None
    if sort == "agent":
        return view.row.agent_name.casefold() if view.row.agent_name else None
    if sort == "events":
        return view.events
    if sort == "first_seen":
        return view.first_seen
    return view.last_seen


def _sorted(views: list[_View], sort: str, direction: str, *, by_rank: bool) -> list[_View]:
    """Sorted on one column in either direction. Nulls go last both ways.

    Ties keep the machine key order, so two loads of the same data never swap
    rows under the cursor. A search orders by match tier first and by the
    column inside a tier. The console always sends a sort, and an exact name
    must not sink below a later machine that only contains the query.
    """
    stable = sorted(views, key=lambda v: v.row.machine_key)
    present = [v for v in stable if _sort_value(v, sort) is not None]
    absent = [v for v in stable if _sort_value(v, sort) is None]
    present.sort(key=lambda v: _sort_value(v, sort), reverse=direction == "desc")
    ordered = present + absent
    if by_rank:
        ordered.sort(key=lambda v: v.search_rank if v.search_rank is not None else 9)
    return ordered


def _refuse(name: str, value: str, legal: tuple[str, ...] | list[str]) -> None:
    raise api_error(
        422,
        f"unknown_{name}",
        f"The {name} '{value}' is not known. Send one of: {', '.join(legal)}.",
    )


def _check(name: str, value: str | None, legal: tuple[str, ...]) -> str | None:
    if value is None or value == "":
        return None
    folded = value.strip().lower()
    if folded not in legal:
        _refuse(name, value, legal)
    return folded


def _check_role(value: str | None, views: list[_View]) -> str | None:
    if value is None or value == "":
        return None
    folded = value.strip().lower()
    held = {(v.role.value or "").lower() for v in views if v.role.value}
    legal = sorted({*ROLE_VOCABULARY, *_ROLE_BUCKETS, *held} - {""})
    if folded not in legal:
        _refuse("role", value, legal)
    return folded


def _row_out(view: _View) -> MachineRowOut:
    row = view.row
    return MachineRowOut(
        key=row.machine_key,
        href=f"/hosts/{quote(row.machine_key, safe='')}",
        name=view.name,
        name_source=view.name_source,
        names=[MachineNameOut(value=value, source=source) for value, source in view.names],
        primary_ip=view.primary_ip,
        address_count=len(view.members),
        addresses=[a.ip for a in view.members[:_ROW_ADDRESSES]],
        container_count=len(view.containers),
        agent=(
            MachineAgentOut(
                id=row.agent_id,
                name=row.agent_name or row.agent_id,
                os=row.os,
                last_report=_ts(row.agent_last_report),
            )
            if row.agent_id
            else None
        ),
        role=view.role,
        events=view.events,
        first_seen=_ts(view.first_seen),
        last_seen=_ts(view.last_seen),
        flags=MachineFlagsOut(
            declared=view.declared,
            conflict=view.conflict,
            broken=view.broken,
            new=view.new,
            rebound=view.rebound,
        ),
    )


# ---------------------------------------------------------------------------
# Routes. /hosts/summary and /hosts/resolve are registered before /hosts/{key}.
# ---------------------------------------------------------------------------


@router.get("/hosts", response_model=MachineListOut)
async def list_machines(
    request: Request,
    q: str | None = Query(None, max_length=253),
    sort: str | None = Query(None, max_length=32),
    dir: str | None = Query(None, max_length=8),
    role: str | None = Query(None, max_length=64),
    agent: str | None = Query(None, max_length=8),
    activity: str | None = Query(None, max_length=8),
    seen: str | None = Query(None, max_length=8),
    declared: str | None = Query(None, max_length=8),
    named: str | None = Query(None, max_length=8),
    health: str | None = Query(None, max_length=16),
    conflict: str | None = Query(None, max_length=8),
    limit: int = Query(_DEFAULT_LIMIT, ge=1, le=_MAX_LIMIT),
    offset: int = Query(0, ge=0),
    settings: Settings = Depends(get_settings_dep),
) -> MachineListOut:
    """One row per machine, searched, filtered, sorted and paged.

    ``q`` matches every machine name from any source, every address (exact,
    then prefix, never in the middle), every MAC, the OS, the role and the
    agent name. It ignores the activity filter. A search orders by match tier
    first and by the requested column inside a tier. Every column sorts in both
    directions and nulls sort last. An unknown filter value is a 422 that
    names the legal values.
    """
    sort_key = _check("sort", sort, _SORTS) or "last_seen"
    direction = _check("dir", dir, _DIRS) or _DEFAULT_DIR[sort_key]
    filters = _Filters(
        q=(q or "").strip() or None,
        agent=_check("agent", agent, _YES_NO),
        activity=_check("activity", activity, _ACTIVITY) or "active",
        seen=_check("seen", seen, _SEEN),
        declared=_check("declared", declared, _YES_NO),
        named=_check("named", named, _YES_NO),
        health=_check("health", health, _HEALTH),
        conflict=_check("conflict", conflict, _YES_NO),
    )
    knobs = _knobs(settings)
    async with request.app.state.db_sessionmaker() as db:
        views = await _estate(db, knobs)
    filters.role = _check_role(role, views)
    kept: list[_View] = []
    for view in views:
        if not _keep(view, filters):
            continue
        if filters.q is not None:
            view.search_rank = _search_rank(view, filters.q)
            if view.search_rank is None:
                continue
        kept.append(view)
    ordered = _sorted(kept, sort_key, direction, by_rank=filters.q is not None)
    page = ordered[offset : offset + limit]
    return MachineListOut(
        rows=[_row_out(view) for view in page],
        total=len(ordered),
        limit=limit,
        offset=offset,
        sort=sort_key,
        dir=direction,
    )


@router.get("/hosts/summary", response_model=MachineSummaryOut)
async def machine_summary(
    request: Request,
    activity: str | None = Query(None, max_length=8),
    settings: Settings = Depends(get_settings_dep),
) -> MachineSummaryOut:
    """The cards above the Hosts list, and the counts in its header menus.

    Each count is the ``total`` of the list with one filter and the same
    ``activity``: ``with_agent`` is ``agent=yes``, ``new_7d`` is ``seen=new``,
    a role count is ``role=<slug>``, ``unknown`` is ``role=unknown``, ``named``
    is ``named=yes``, ``never_built`` is ``health=broken``, ``needs_attention``
    is ``health=attention`` and ``conflicts`` is ``conflict=yes``. Needs
    attention does not count conflicts, so no machine is counted twice on the
    cards. ``activity`` defaults to ``all``: the cards count every machine. The
    header menus send the activity of the list, so a menu count is the number
    of rows the filter shows.
    """
    scope = _check("activity", activity, _ACTIVITY) or "all"
    knobs = _knobs(settings)
    async with request.app.state.db_sessionmaker() as db:
        views = [v for v in await _estate(db, knobs) if _keep(v, _Filters(activity=scope))]
        last_sweep = await db.scalar(
            select(DossierRun.finished_at)
            .where(DossierRun.finished_at.is_not(None))
            .order_by(DossierRun.finished_at.desc())
            .limit(1)
        )
    roles: dict[str, int] = {}
    for view in views:
        if view.role.state in ("declared", "inferred") and view.role.value:
            slug = view.role.value.lower()
            roles[slug] = roles.get(slug, 0) + 1
    for bucket in _ROLE_BUCKETS:
        roles[bucket] = sum(1 for view in views if view.role.state == bucket)
    named = sum(1 for view in views if view.name is not None)
    with_agent = sum(1 for view in views if view.row.agent_id is not None)
    stale_hours = (
        round((_naive(knobs.now) - last_sweep).total_seconds() / 3600.0, 1)
        if last_sweep is not None
        else None
    )
    return MachineSummaryOut(
        machines=len(views),
        addresses=sum(len(view.members) for view in views),
        with_agent=with_agent,
        without_agent=len(views) - with_agent,
        new_7d=sum(1 for view in views if view.new),
        named=named,
        unnamed=len(views) - named,
        roles=roles,
        needs_attention=sum(1 for view in views if view.needs_attention),
        conflicts=sum(1 for view in views if view.conflict),
        never_built=sum(1 for view in views if view.broken),
        last_sweep_at=_ts(last_sweep),
        stale_hours=stale_hours,
    )


_NO_HOST_HINT = "No machine holds this value. Run a sweep, or search the Hosts list."


@router.get("/hosts/resolve", response_model=MachineResolveOut)
async def resolve_machine(
    request: Request, value: str = Query("", max_length=253)
) -> MachineResolveOut:
    """An address, a name, a MAC or an agent id to a machine key. 404 when none.

    A name two machines share resolves to neither. The console sends an address
    in a ``/hosts/<address>`` link here and opens the machine it names.
    """
    if not value.strip():
        raise api_error(422, "value_required", "Send the address, name, MAC or agent id.")
    async with request.app.state.db_sessionmaker() as db:
        held = await host_machines.resolve_membership(db, value)
    if held is None or not held.primary_ip:
        raise api_error(404, "no_host", _NO_HOST_HINT)
    matched: _AsMatched = (
        _KEY_MATCH.get(held.key.split(":", 1)[0], "agent")
        if held.matched == "key"
        else held.matched
    )
    return MachineResolveOut(key=held.key, primary_ip=held.primary_ip, matched=matched)


@router.get("/hosts/{key}", response_model=MachineDetailOut)
async def get_machine(
    request: Request, key: str, settings: Settings = Depends(get_settings_dep)
) -> MachineDetailOut:
    """One machine: every address with its type, the containers, the MACs and the merges.

    ``dossier`` is the per-address dossier of the primary address. A key that an
    earlier sweep merged into this machine answers with this machine.
    """
    knobs = _knobs(settings)
    async with request.app.state.db_sessionmaker() as db:
        views = await _estate(db, knobs)
    view = next((v for v in views if v.row.machine_key == key), None)
    if view is None:
        view = next((v for v in views if key in (v.row.merged_from_json or [])), None)
    if view is None:
        raise api_error(404, "no_host", _NO_HOST_HINT)
    base = _row_out(view).model_dump(exclude={"addresses"})
    primary = view.primary_ip
    dossier = await _current_dossier(request, primary, settings) if primary else None
    return MachineDetailOut(
        **base,
        addresses=[
            MachineAddressOut(
                ip=a.ip,
                kind=a.kind,
                primary=a.ip == primary,
                first_seen=_ts(a.first_seen),
                last_seen=_ts(a.last_seen),
                events=a.events,
            )
            for a in view.members
        ],
        containers=[
            MachineContainerOut(
                ip=c.ip, first_seen=_ts(c.first_seen), last_seen=_ts(c.last_seen), events=c.events
            )
            for c in view.containers
        ],
        macs=[m for m in (normalize_mac(str(m)) for m in view.row.macs_json or []) if m],
        merged_from=[str(k) for k in view.row.merged_from_json or []],
        dossier=dossier,
    )


__all__ = [
    "MachineDetailOut",
    "MachineListOut",
    "MachineResolveOut",
    "MachineRowOut",
    "MachineSummaryOut",
    "get_machine",
    "list_machines",
    "machine_summary",
    "resolve_machine",
]
