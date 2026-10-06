"""The estate behind one host's baseline: how many hosts hold each member.

Novelty fired on the first sighting of a member against one host's own set.
A port that forty hosts already served weighed as much as a port no host had
ever served, and a software rollout read as forty novelties.

Prevalence is read from the stored host profiles after a build, so it costs
no search. For each set dimension it counts the hosts whose baseline holds
each member. The prior sweep reads it for the members that are new to a host:

* fewer than ``rare_below`` hosts hold the member: the member is estate-rare,
  and the observation is born heavier;
* more than ``common_share`` of the profiled hosts hold it, and at least
  ``rare_below`` of them: the member is estate-common. It is a trait of the
  estate, and it forms no observation;
* in between: an ordinary novelty.

The table is refreshed when a build is newer than the last refresh. The
prior sweep checks that on every run, so a build that ran anywhere is read on
the next sweep. ``refresh_estate`` is the hook a build can call itself.

The peer source lives here too. :func:`peer_source` names the peer group of
one host: its confident role first, and when it has none, the learned group
the estate model gave it (``soc_ai.hunting.estate_model``). A learned group
serves only while ``estate_model_enabled`` is on and the newest fit is
measured and younger than 48 hours. :func:`peer_profiles` reads the profiles
of either kind of group.
"""

from __future__ import annotations

import logging
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import delete, func, insert, select
from sqlalchemy.ext.asyncio import AsyncSession

from soc_ai.dossier.profile import _CATEGORICAL
from soc_ai.hunting.priors import DEFAULT_MIN_KNOWN_DAYS, known_members
from soc_ai.hunting.roles import CONFIDENT_ROLE, name_keys, role_for, roles
from soc_ai.store import estate_model as learned_store
from soc_ai.store.entity_profiles import (
    ProfileRow,
    load_dimension,
    profiles_for_role,
    stamp_roles,
)
from soc_ai.store.models import EntityProfile, Investigation, MemberPrevalence

__all__ = [
    "DEFAULT_COMMON_SHARE",
    "DEFAULT_RARE_HOSTS",
    "PREVALENCE_DIMENSIONS",
    "SCOPE_MIN_HOSTS",
    "TP_WINDOW_PAD_HOURS",
    "EstateRefresh",
    "EstateView",
    "LearnedPeers",
    "PeerSource",
    "PeerView",
    "confirmed_windows",
    "ensure_estate",
    "estate_is_stale",
    "held_members",
    "peer_profiles",
    "peer_source",
    "prevalence_for",
    "profiled_hosts",
    "refresh_estate",
    "windows_for",
]

_LOGGER = logging.getLogger(__name__)

# The set dimensions. The shaped dimensions hold hours and rates, not members.
PREVALENCE_DIMENSIONS: tuple[str, ...] = tuple(row[0] for row in _CATEGORICAL)

# The defaults of the two settings. Below 3 hosts a member is estate-rare.
# Above 20 % of the profiled hosts, and at least 3, it is estate-common.
DEFAULT_RARE_HOSTS = 3
DEFAULT_COMMON_SHARE = 0.2

# How many hosts must gain one member in one sweep before the sweep records
# the spread as a second observation on each of them.
SCOPE_MIN_HOSTS = 3

# The stamp row: the dimension no profile carries, with an empty member.
_STAMP_DIMENSION = "*"

# The coverage states whose sets describe what a host does.
_HELD = ("measured", "learning")

# SQLite binds at most 999 parameters in older builds. The member lists stay
# well under that per query.
_CHUNK = 500


@dataclass(frozen=True)
class EstateView:
    """How common the members of one dimension are, for one evaluation.

    ``measured`` is the number of profiled hosts on the dimension. ``hosts``
    maps a member to the number of hosts whose baseline holds it. A member
    the map does not name is held by no host.
    """

    measured: int
    hosts: Mapping[str, int]
    rare_below: int = DEFAULT_RARE_HOSTS
    common_share: float = DEFAULT_COMMON_SHARE

    def holders(self, member: str) -> int:
        return int(self.hosts.get(str(member), 0))

    def rare(self, member: str) -> bool:
        """Fewer than ``rare_below`` hosts hold the member."""
        return self.holders(member) < self.rare_below

    def common(self, member: str) -> bool:
        """More than ``common_share`` of the profiled hosts hold it, and enough hosts.

        The floor of ``rare_below`` hosts keeps a small estate honest. In an
        estate of five hosts, 20 % is one host, and one host is not a trait
        of the estate.
        """
        held = self.holders(member)
        return held >= self.rare_below and held > self.common_share * max(0, self.measured)


@dataclass(frozen=True)
class PeerView:
    """How the peers of one entity, in the same confident role, hold its members.

    ``peers`` counts the other hosts in the role at the confidence gate with
    a scorable set on the dimension. ``holders`` maps a member to the number
    of those peers whose baseline knows it.
    """

    role: str
    peers: int
    holders: Mapping[str, int]
    min_peers: int = 5

    @property
    def measurable(self) -> bool:
        """Enough peers to say anything about the role."""
        return self.peers >= self.min_peers

    def held_by(self, member: str) -> int:
        return int(self.holders.get(str(member), 0))

    def trait(self, member: str) -> bool:
        """Most peers hold the member: a trait of the role, not of this host."""
        return self.measurable and self.held_by(member) > self.peers / 2.0


@dataclass(frozen=True)
class EstateRefresh:
    """What one refresh read and wrote."""

    hosts: int
    members: int
    built_at: datetime
    roles_stamped: int = 0


def held_members(vector: Any, *, exclude: Iterable[tuple[datetime, datetime]] = ()) -> set[str]:
    """The members a stored set holds, as the baseline knows them.

    The same rule the novelty test reads: seen on two days or more, and not
    first seen inside a confirmed attack. A member one host saw once counts
    toward no estate trait.
    """
    return {
        m
        for m in known_members(vector, min_days=DEFAULT_MIN_KNOWN_DAYS, exclude=tuple(exclude))
        if m
    }


# How far around a confirmed investigation the baseline leaves the host out.
# The run time is not the event time: an alert is triaged minutes to hours
# after it fired, and the attack ran before and after the one alert.
TP_WINDOW_PAD_HOURS = 24

# How far back a confirmed investigation still shapes a baseline: the longest
# profile window, with room for the lag.
_TP_LOOKBACK_DAYS = 100


async def confirmed_windows(
    db: AsyncSession, *, now: datetime | None = None
) -> dict[str, list[tuple[datetime, datetime]]]:
    """The windows an investigation confirmed as a true positive, per host key.

    Keyed by every address and name the investigation names: the source, the
    destination and the host name, folded to lower case with its short label.
    A synthetic evaluation run and a pipeline fallback confirm nothing.
    """
    at = (now or datetime.now(UTC)).astimezone(UTC).replace(tzinfo=None)
    rows = (
        await db.execute(
            select(
                Investigation.src_ip,
                Investigation.dest_ip,
                Investigation.host_name,
                Investigation.created_at,
                Investigation.finished_at,
            ).where(
                Investigation.verdict == "true_positive",
                Investigation.status == "complete",
                Investigation.is_synth_eval.is_(False),
                Investigation.is_fallback.isnot(True),
                Investigation.created_at >= at - timedelta(days=_TP_LOOKBACK_DAYS),
            )
        )
    ).all()
    pad = timedelta(hours=TP_WINDOW_PAD_HOURS)
    out: dict[str, list[tuple[datetime, datetime]]] = {}
    for src, dest, host, created, finished in rows:
        if created is None:
            continue
        window = (
            (created - pad).replace(tzinfo=UTC),
            ((finished or created) + pad).replace(tzinfo=UTC),
        )
        for key in _keys(src, dest, host):
            out.setdefault(key, []).append(window)
    return out


def _keys(*values: Any) -> set[str]:
    keys: set[str] = set()
    for value in values:
        text = str(value or "").strip().lower()
        if not text:
            continue
        keys.add(text)
        keys.add(text.split(".", 1)[0] if not text.replace(".", "").isdigit() else text)
    return keys


def windows_for(
    windows: Mapping[str, list[tuple[datetime, datetime]]], entity_key: str
) -> list[tuple[datetime, datetime]]:
    """The confirmed windows of one entity, by address or by folded host name."""
    found: list[tuple[datetime, datetime]] = []
    for key in _keys(entity_key):
        for window in windows.get(key, ()):
            if window not in found:
                found.append(window)
    return found


async def refresh_estate(db: AsyncSession) -> EstateRefresh:
    """Count, per dimension and member, the hosts whose stored set holds it.

    Replaces the whole table in one transaction. A partial table would read
    a member as held by fewer hosts than hold it, which is the false rarity
    this table exists to prevent.
    """
    rows = (
        await db.execute(
            select(
                EntityProfile.entity_key, EntityProfile.dimension, EntityProfile.vector_json
            ).where(
                EntityProfile.entity_kind == "host",
                EntityProfile.dimension.in_(PREVALENCE_DIMENSIONS),
                EntityProfile.coverage.in_(_HELD),
            )
        )
    ).all()
    # The role on every row first, so a peer group reads the same map the
    # role priors read. The build writes each row with no role.
    role_map = await roles(db)
    stamped = await stamp_roles(db, lambda key: role_for(role_map, key))
    windows = await confirmed_windows(db)
    holders: dict[tuple[str, str], set[str]] = {}
    hosts: set[str] = set()
    for entity_key, dimension, vector in rows:
        hosts.add(str(entity_key))
        for member in held_members(vector, exclude=windows_for(windows, str(entity_key))):
            holders.setdefault((str(dimension), member[:255]), set()).add(str(entity_key))

    at = datetime.now(UTC).replace(tzinfo=None)
    await db.execute(delete(MemberPrevalence))
    payload = [
        {"dimension": dimension, "member": member, "hosts": len(keys), "built_at": at}
        for (dimension, member), keys in holders.items()
    ]
    payload.append(
        {"dimension": _STAMP_DIMENSION, "member": "", "hosts": len(hosts), "built_at": at}
    )
    await db.execute(insert(MemberPrevalence), payload)
    await db.commit()
    return EstateRefresh(hosts=len(hosts), members=len(holders), built_at=at, roles_stamped=stamped)


async def estate_is_stale(db: AsyncSession) -> bool:
    """Whether a build wrote a host set after the last refresh, or none ran yet."""
    stamp = (
        await db.execute(
            select(MemberPrevalence.built_at).where(
                MemberPrevalence.dimension == _STAMP_DIMENSION, MemberPrevalence.member == ""
            )
        )
    ).scalar_one_or_none()
    if stamp is None:
        return True
    newest = (
        await db.execute(
            select(func.max(EntityProfile.built_at)).where(
                EntityProfile.entity_kind == "host",
                EntityProfile.dimension.in_(PREVALENCE_DIMENSIONS),
            )
        )
    ).scalar_one_or_none()
    return newest is not None and newest > stamp


async def ensure_estate(db: AsyncSession) -> str | None:
    """Refresh the table when a build is newer than it. A note when it ran."""
    if not await estate_is_stale(db):
        return None
    done = await refresh_estate(db)
    return (
        f"estate prevalence: read {done.hosts} host(s), counted "
        f"{done.members} member(s) across the set dimensions and wrote "
        f"{done.roles_stamped} role(s)"
    )


async def prevalence_for(
    db: AsyncSession, dimension: str, members: Iterable[str]
) -> dict[str, int]:
    """How many hosts hold each of these members. A member held by none is absent."""
    wanted = sorted({str(m)[:255] for m in members if str(m)})
    out: dict[str, int] = {}
    for start in range(0, len(wanted), _CHUNK):
        chunk = wanted[start : start + _CHUNK]
        rows = (
            await db.execute(
                select(MemberPrevalence.member, MemberPrevalence.hosts).where(
                    MemberPrevalence.dimension == dimension,
                    MemberPrevalence.member.in_(chunk),
                )
            )
        ).all()
        out.update({str(member): int(hosts) for member, hosts in rows})
    return out


async def profiled_hosts(db: AsyncSession, dimension: str) -> int:
    """How many hosts hold a stored set on this dimension."""
    value = (
        await db.execute(
            select(func.count(func.distinct(EntityProfile.entity_key))).where(
                EntityProfile.entity_kind == "host",
                EntityProfile.dimension == dimension,
                EntityProfile.coverage.in_(_HELD),
            )
        )
    ).scalar_one_or_none()
    return int(value or 0)


@dataclass(frozen=True)
class PeerSource:
    """Where the peers of one host come from: its role, or its learned group.

    ``label`` is the word the peer sentence uses: the role, or "learned group
    N". ``cache_key`` keeps a role and a learned group apart in a sweep's
    cache, whatever the role is called.
    """

    kind: str
    label: str
    role: str | None = None
    group_id: int | None = None

    @property
    def cache_key(self) -> str:
        return self.label if self.kind == "role" else f"\x00learned:{self.group_id}"


class LearnedPeers:
    """The learned groups of the usable fit, read once and held for one sweep.

    ``enabled`` is the ``estate_model_enabled`` setting. Off, the reader reads
    nothing and every host without a confident role has no peer group, as
    before the estate model existed.
    """

    def __init__(self, *, enabled: bool = False) -> None:
        self.enabled = enabled
        self._loaded = False
        self._group_of: dict[str, int] = {}
        self._members: dict[int, list[str]] = {}

    async def _load(self, db: AsyncSession) -> None:
        self._loaded = True
        if not self.enabled:
            return
        fit = await learned_store.usable_fit(db)
        if fit is None or fit.model_sha256 is None:
            return
        self._group_of = await learned_store.learned_map(db, model_sha256=fit.model_sha256)
        for key, group in sorted(self._group_of.items()):
            self._members.setdefault(group, []).append(key)

    async def group_of(self, db: AsyncSession, entity_key: str) -> int | None:
        """The learned group of one host, by its key or its folded host name."""
        if not self._loaded:
            await self._load(db)
        if entity_key in self._group_of:
            return self._group_of[entity_key]
        for key in name_keys(entity_key):
            if key in self._group_of:
                return self._group_of[key]
        return None

    def members(self, group_id: int) -> list[str]:
        return list(self._members.get(group_id, ()))


async def peer_source(
    db: AsyncSession,
    *,
    entity_key: str,
    role: str | None,
    confidence: float,
    learned: LearnedPeers | None = None,
) -> PeerSource | None:
    """The peer group of one host: its confident role first, then its learned group.

    A declared role carries full confidence, and an inferred one counts at
    0.9 or more. A host below that bar reads its learned group when the
    estate model has a usable fit. None when the host has neither.
    """
    if role is not None and confidence >= CONFIDENT_ROLE:
        return PeerSource(kind="role", label=role, role=role)
    if learned is None:
        return None
    group = await learned.group_of(db, entity_key)
    if group is None:
        return None
    return PeerSource(kind="learned", label=f"learned group {group}", group_id=group)


async def peer_profiles(
    db: AsyncSession,
    source: PeerSource,
    *,
    dimension: str,
    learned: LearnedPeers | None = None,
) -> list[ProfileRow]:
    """Every scorable profile of the group on one dimension.

    A role reads the role column at the confidence gate, as it always has. A
    learned group reads its members' rows in slices of 500 keys.
    """
    if source.kind == "role" and source.role is not None:
        return await profiles_for_role(
            db, role=source.role, dimension=dimension, min_confidence=CONFIDENT_ROLE
        )
    if learned is None or source.group_id is None:
        return []
    keys = learned.members(source.group_id)
    out: list[ProfileRow] = []
    for start in range(0, len(keys), _CHUNK):
        rows = await load_dimension(
            db, entity_kind="host", dimension=dimension, entity_keys=keys[start : start + _CHUNK]
        )
        out.extend(row for _key, row in sorted(rows.items()) if row.is_scorable)
    return out
