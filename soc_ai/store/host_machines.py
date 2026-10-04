"""Machines: the set of addresses soc-ai holds to be one device.

The per-address dossier (:mod:`soc_ai.store.host_dossier`) is keyed on the IP,
and the Hosts screen used to show one row per address. Production had 14 rows
for one proxy and 10 nameless rows for one workstation. A machine sits above
the address rows: one row per device, its addresses listed under it.

The module has two halves, kept apart on purpose:

* :func:`cluster_machines` is a PURE function. It takes per-address facts, the
  agents' claims, the DHCP leases, the container sightings and the machines of
  the previous sweep, and returns the machines. No I/O, no clock. Every join
  rule is testable from hand-built input.
* The async functions below it read the inputs from the store, write the result
  back, and answer the reads the API and the joins make.

The join rules, in order. A rule never moves an address a stronger rule placed.

1. **Agent.** One agent is one machine. Its addresses are the internal
   ``host.ip`` values it reported. An address two agents report belongs to
   neither: Docker's ``172.17.0.1`` is on every Docker host.
2. **Bridge and container.** An agent that reports a bridge gateway (an IPv4
   address ending in ``.1``) owns that bridge's /24. An address inside it that
   the agent's endpoint sensor sees is a container on the machine, whatever
   other datasets saw it: zeek sees a container whose traffic leaves the
   bridge. Two exceptions keep the address a machine: another agent claims it
   (reports it, or sees it inside a bridge of its own), or a DHCP lease names
   it. A container is not a machine row.
3. **DHCP lease.** An address a lease gave to one MAC belongs to the machine of
   that MAC. An agent owns a MAC when it reports it and reports 8 MACs or fewer;
   an agent with 349 MACs (veth pairs) owns none, or it would absorb every DHCP
   device on the network. A MAC no agent owns is a machine of its own. When two
   MACs held one address in the window, the newer lease wins.
4. **Unique name.** A network-only address whose strong DNS name matches the
   short name of one agent machine joins it. A short name two machines share
   joins neither.
5. **Single address.** An address no rule placed is a machine of its own.
"""

from __future__ import annotations

import contextlib
import dataclasses
import ipaddress
import re
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any, Literal

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from soc_ai.dossier.resolve import resolve_field
from soc_ai.dossier.types import DhcpLease, identity_bearing_ip, is_service_or_reverse_name
from soc_ai.store.models import HostDossier, HostDossierField, HostMachine

AddressKind = Literal["agent", "dhcp", "name", "network", "container"]
NameSource = Literal["declared", "agent", "dhcp", "dns", "ntlm", "other"]

ADDRESS_KINDS: tuple[AddressKind, ...] = ("agent", "dhcp", "name", "network", "container")
NAME_SOURCES: tuple[NameSource, ...] = ("declared", "agent", "dhcp", "dns", "ntlm", "other")

# An agent that reports more hardware addresses than this owns none of them. A
# container host reports one per veth pair (one production agent reported 349), and owning
# them would hand it every DHCP device whose MAC it once saw on a bridge.
MAX_OWNED_MACS = 8

# Key strength, for the merge rule: an older, weaker key folds into a stronger
# one that now holds its addresses. Never sideways: two MACs are two devices.
_KEY_RANK = {"ip": 0, "mac": 1, "agent": 2}

_NAME_SOURCE_RANK: dict[str, int] = {source: rank for rank, source in enumerate(NAME_SOURCES)}
_AS_NAME_SOURCE: dict[str, NameSource] = {source: source for source in NAME_SOURCES}

_HOSTNAME_MIN_LEN = 3
_EPOCH = datetime(1970, 1, 1)

__all__ = [
    "ADDRESS_KINDS",
    "NAME_SOURCES",
    "AddressFacts",
    "AgentClaim",
    "Clustering",
    "ContainerSighting",
    "DhcpLease",
    "Machine",
    "MachineAddress",
    "MachineName",
    "Membership",
    "PriorMachine",
    "address_sort_key",
    "cluster_machines",
    "entity_expansion",
    "load_address_facts",
    "load_prior",
    "normalize_mac",
    "persist_clustering",
    "resolve_membership",
    "short_name",
]


# ---------------------------------------------------------------------------
# Input and output types
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class AddressFacts:
    """What the store holds about one address in the census."""

    ip: str
    events: int = 0
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    # The operator's declared hostname on this address.
    declared_name: str | None = None
    # The hostname the resolver asserts from the inference lane, and its source
    # in the NameSource vocabulary.
    inferred_name: str | None = None
    inferred_name_source: str | None = None
    # The strong DNS name the network's answers agree on for this address.
    dns_name: str | None = None
    os: str | None = None


@dataclass(frozen=True)
class AgentClaim:
    """One agent: its id, its name and every address and MAC it reported."""

    agent_id: str
    name: str
    os: str | None = None
    macs: tuple[str, ...] = ()
    # Every identity-bearing address the agent reported, shared ones included.
    addresses: tuple[str, ...] = ()
    last_report: datetime | None = None
    # The agent's own documents in the window. The machine counts them once.
    docs: int = 0


@dataclass(frozen=True)
class ContainerSighting:
    """An address that one agent's endpoint sensor sees. Other sensors may too."""

    ip: str
    agent_id: str


@dataclass(frozen=True)
class PriorMachine:
    """A machine the previous sweep wrote, for the stable key and the merge."""

    key: str
    addresses: tuple[str, ...] = ()
    macs: tuple[str, ...] = ()
    merged_from: tuple[str, ...] = ()
    first_seen: datetime | None = None


@dataclass(frozen=True)
class MachineAddress:
    ip: str
    kind: AddressKind


@dataclass(frozen=True)
class MachineName:
    value: str
    source: NameSource


@dataclass(frozen=True)
class Machine:
    """One device: its addresses, its names and its identity."""

    key: str
    addresses: tuple[MachineAddress, ...]
    primary_ip: str | None
    name: str | None = None
    name_source: NameSource | None = None
    names: tuple[MachineName, ...] = ()
    agent_id: str | None = None
    agent_name: str | None = None
    agent_last_report: datetime | None = None
    os: str | None = None
    macs: tuple[str, ...] = ()
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    events: int = 0
    merged_from: tuple[str, ...] = ()

    @property
    def members(self) -> tuple[MachineAddress, ...]:
        """The addresses that are the machine's own, containers excluded."""
        return tuple(a for a in self.addresses if a.kind != "container")

    @property
    def containers(self) -> tuple[MachineAddress, ...]:
        return tuple(a for a in self.addresses if a.kind == "container")


@dataclass(frozen=True)
class Clustering:
    """The sweep's machines, plus what the rules declined to decide."""

    machines: tuple[Machine, ...]
    # Addresses two or more agents report. They belong to no agent.
    shared: tuple[str, ...] = ()
    # Earlier machine key -> the machine that absorbed it.
    merged: dict[str, str] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Small normalisers
# ---------------------------------------------------------------------------


def normalize_mac(value: Any) -> str | None:
    """Any written MAC form as ``aa:bb:cc:dd:ee:ff``, or ``None``.

    Broadcast and all-zero are placeholders, not hardware addresses.
    """
    if not isinstance(value, str):
        return None
    digits = re.sub(r"[^0-9a-fA-F]", "", value).lower()
    if len(digits) != 12 or digits in ("0" * 12, "f" * 12):
        return None
    return ":".join(digits[i : i + 2] for i in range(0, 12, 2))


def short_name(value: str) -> str:
    """The first label of a name, case-folded: ``Depot.example.test`` -> ``depot``."""
    return value.strip().rstrip(".").split(".", 1)[0].casefold()


def address_sort_key(ip: str | None) -> tuple[int, int]:
    """Numeric order for an address: IPv4 before IPv6, then by value."""
    if not ip:
        return (9, 0)
    try:
        parsed = ipaddress.ip_address(ip)
    except ValueError:
        return (8, 0)
    return (parsed.version, int(parsed))


def _clean_name(value: str | None, *, self_reported: bool) -> str | None:
    """A usable name, or ``None``. The dossier's own hostname rules apply."""
    if not value or not isinstance(value, str):
        return None
    # Lazy, as in `enrichment.host_dossier`: `infer` is pure and cheap, and the
    # one place the hostname rules are spelled.
    from soc_ai.dossier.infer import _clean_hostname  # noqa: PLC0415

    return _clean_hostname(value, self_reported=self_reported)


def _key_kind(key: str) -> str:
    return key.split(":", 1)[0]


def _ts(value: datetime | None) -> datetime:
    """A sortable timestamp: naive UTC, the epoch for an absence."""
    if value is None:
        return _EPOCH
    if value.tzinfo is not None:
        return value.astimezone(UTC).replace(tzinfo=None)
    return value


def _min_dt(*values: datetime | None) -> datetime | None:
    held = [_ts(v) for v in values if v is not None]
    return min(held) if held else None


def _max_dt(*values: datetime | None) -> datetime | None:
    held = [_ts(v) for v in values if v is not None]
    return max(held) if held else None


# ---------------------------------------------------------------------------
# The pure clustering
# ---------------------------------------------------------------------------


@dataclass
class _Draft:
    key: str
    agent: AgentClaim | None = None
    mac: str | None = None
    kinds: dict[str, AddressKind] = field(default_factory=dict)
    leases: list[DhcpLease] = field(default_factory=list)

    def place(self, ip: str, kind: AddressKind) -> None:
        self.kinds[ip] = kind


def _bridge_networks(agent: AgentClaim) -> list[ipaddress.IPv4Network]:
    """The /24 of each bridge gateway the agent reports (an IPv4 ``.1``)."""
    out: list[ipaddress.IPv4Network] = []
    for raw in agent.addresses:
        try:
            parsed = ipaddress.ip_address(raw)
        except ValueError:
            continue
        if isinstance(parsed, ipaddress.IPv4Address) and int(parsed) & 0xFF == 1:
            out.append(ipaddress.IPv4Network(f"{parsed}/24", strict=False))
    return out


def _in_networks(ip: str, networks: Sequence[ipaddress.IPv4Network]) -> bool:
    try:
        parsed = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return isinstance(parsed, ipaddress.IPv4Address) and any(parsed in n for n in networks)


def _newest_lease(leases: Iterable[DhcpLease]) -> DhcpLease | None:
    """The newest lease, by last sighting, then first sighting, then MAC."""
    ranked = sorted(
        leases, key=lambda lease: (_ts(lease.last_seen), _ts(lease.first_seen), lease.mac)
    )
    return ranked[-1] if ranked else None


def _dedupe_agents(agents: Iterable[AgentClaim]) -> list[AgentClaim]:
    seen: dict[str, AgentClaim] = {}
    for agent in agents:
        if agent.agent_id and agent.agent_id not in seen:
            seen[agent.agent_id] = agent
    return list(seen.values())


def cluster_machines(
    addresses: Iterable[AddressFacts],
    agents: Iterable[AgentClaim] = (),
    leases: Iterable[DhcpLease] = (),
    sightings: Iterable[ContainerSighting] = (),
    prior: Iterable[PriorMachine] = (),
) -> Clustering:
    """Group the census addresses into machines. Pure: no I/O, no clock.

    Only addresses in *addresses* are placed: the census decides what exists,
    and an agent's address outside the internal ranges is not a host here. The
    rules are the five in the module docstring, applied in order. A rule never
    moves an address that a stronger rule placed.
    """
    state = _Clusterer(addresses, agents)
    leases = list(leases)
    state.place_agents()
    state.place_containers(sightings, leases)
    state.place_leases(leases)
    state.place_names()
    state.place_rest()
    machines = [
        _finish(target, state.facts, state.winning)
        for target in state.drafts.values()
        if any(kind != "container" for kind in target.kinds.values())
    ]
    machines, merged = _merge_prior(machines, list(prior))
    machines.sort(key=lambda m: m.key)
    return Clustering(machines=tuple(machines), shared=tuple(state.shared), merged=merged)


class _Clusterer:
    """The working state of one clustering: what is placed, and where."""

    def __init__(self, addresses: Iterable[AddressFacts], agents: Iterable[AgentClaim]) -> None:
        self.facts: dict[str, AddressFacts] = {}
        for fact in addresses:
            ip = identity_bearing_ip(fact.ip)
            if ip is not None and ip not in self.facts:
                self.facts[ip] = fact
        self.agents = _dedupe_agents(agents)
        self.placed: dict[str, str] = {}  # ip -> draft key
        self.drafts: dict[str, _Draft] = {
            f"agent:{agent.agent_id}": _Draft(key=f"agent:{agent.agent_id}", agent=agent)
            for agent in self.agents
        }
        self.reporters: dict[str, set[str]] = {}
        self.shared: list[str] = []
        self.winning: dict[str, DhcpLease] = {}

    def _draft(self, key: str) -> _Draft:
        held = self.drafts.get(key)
        if held is None:
            held = self.drafts[key] = _Draft(key=key)
        return held

    def _place(self, ip: str, key: str, kind: AddressKind) -> None:
        self._draft(key).place(ip, kind)
        self.placed[ip] = key

    def _free(self, ip: str) -> bool:
        return ip in self.facts and ip not in self.placed

    def place_agents(self) -> None:
        """Rule 1. An address one agent reports is that agent's. Two agents: neither."""
        for agent in self.agents:
            for raw in agent.addresses:
                ip = identity_bearing_ip(raw)
                if ip is not None:
                    self.reporters.setdefault(ip, set()).add(agent.agent_id)
        self.shared = sorted(
            (ip for ip, ids in self.reporters.items() if len(ids) > 1 and ip in self.facts),
            key=address_sort_key,
        )
        for ip, ids in self.reporters.items():
            if len(ids) == 1 and ip in self.facts:
                self._place(ip, f"agent:{next(iter(ids))}", "agent")

    def place_containers(
        self, sightings: Iterable[ContainerSighting], leases: Iterable[DhcpLease]
    ) -> None:
        """Rule 2. An address in an agent's bridge that its endpoint sensor sees.

        Another agent's claim or a DHCP lease keeps the address a machine. A
        lease names a device, and two Docker hosts each own 172.17.0.0/24, so
        two claims on one address are two containers or none.
        """
        bridges = {agent.agent_id: _bridge_networks(agent) for agent in self.agents}
        leased = {lease.ip for lease in _clean_leases(leases)}
        claims: dict[str, set[str]] = {}
        for sighting in sightings:
            ip = identity_bearing_ip(sighting.ip)
            if ip is None or not self._free(ip) or ip in self.reporters or ip in leased:
                continue
            networks = bridges.get(sighting.agent_id) or []
            if networks and _in_networks(ip, networks):
                claims.setdefault(ip, set()).add(sighting.agent_id)
        for ip, owners in claims.items():
            if len(owners) == 1:
                self._place(ip, f"agent:{next(iter(owners))}", "container")

    def place_leases(self, leases: Iterable[DhcpLease]) -> None:
        """Rule 3. The newest lease's MAC decides; an agent owns at most 8 MACs."""
        owners: dict[str, set[str]] = {}
        for agent in self.agents:
            macs = {mac for raw in agent.macs if (mac := normalize_mac(raw)) is not None}
            if len(macs) <= MAX_OWNED_MACS:
                for mac in macs:
                    owners.setdefault(mac, set()).add(agent.agent_id)
        clean = _clean_leases(leases)
        by_ip: dict[str, list[DhcpLease]] = {}
        for lease in clean:
            by_ip.setdefault(lease.ip, []).append(lease)
        for ip, held in by_ip.items():
            newest = _newest_lease(held)
            if newest is not None:
                self.winning[ip] = newest
        for ip in sorted(self.winning, key=address_sort_key):
            if not self._free(ip):
                continue
            lease = self.winning[ip]
            mac_owners = owners.get(lease.mac, set())
            if len(mac_owners) == 1:
                self._place(ip, f"agent:{next(iter(mac_owners))}", "dhcp")
            else:
                self._draft(f"mac:{lease.mac}").mac = lease.mac
                self._place(ip, f"mac:{lease.mac}", "dhcp")
        # Every machine keeps the leases that name it: for an agent the leases
        # of the MACs it owns, for a MAC machine the leases of its MAC.
        for target in self.drafts.values():
            owned: set[str] = set()
            if target.agent is not None:
                mine = {target.agent.agent_id}
                owned = {mac for mac, ids in owners.items() if ids == mine}
            elif target.mac is not None:
                owned = {target.mac}
            target.leases.extend(lease for lease in clean if lease.mac in owned)

    def place_names(self) -> None:
        """Rule 4. A strong DNS name whose short name only one agent machine holds."""
        index: dict[str, set[str]] = {}
        for key, target in self.drafts.items():
            for value in _draft_names(target, self.facts):
                index.setdefault(short_name(value), set()).add(key)
        for ip in sorted(self.facts, key=address_sort_key):
            if not self._free(ip):
                continue
            dns = _clean_name(self.facts[ip].dns_name, self_reported=False)
            if dns is None:
                continue
            keys = index.get(short_name(dns), set())
            if len(keys) == 1:
                key = next(iter(keys))
                if _key_kind(key) == "agent":
                    self._place(ip, key, "name")

    def place_rest(self) -> None:
        """Rule 5. Every address no rule placed is a machine of its own."""
        for ip in self.facts:
            if self._free(ip):
                self._place(ip, f"ip:{ip}", "network")


def _clean_leases(leases: Iterable[DhcpLease]) -> list[DhcpLease]:
    """The leases with a usable address and MAC, both normalised."""
    out: list[DhcpLease] = []
    for lease in leases:
        ip = identity_bearing_ip(lease.ip)
        mac = normalize_mac(lease.mac)
        if ip is not None and mac is not None:
            out.append(dataclasses.replace(lease, ip=ip, mac=mac))
    return out


def _draft_names(target: _Draft, facts: Mapping[str, AddressFacts]) -> list[str]:
    """The names a draft answers to so far, for the unique-name index."""
    out: list[str] = []
    if target.agent is not None and target.agent.name.strip():
        out.append(target.agent.name)
    for lease in target.leases:
        name = _clean_name(lease.hostname, self_reported=True)
        if name is not None:
            out.append(name)
    for ip in target.kinds:
        declared = (facts.get(ip) or AddressFacts(ip=ip)).declared_name
        if declared and declared.strip():
            out.append(declared.strip())
    return out


def _primary(
    target: _Draft, facts: Mapping[str, AddressFacts], winning: Mapping[str, DhcpLease]
) -> str | None:
    """The agent address with the most events, else the newest lease, else the busiest."""

    def busiest(ips: list[str]) -> str | None:
        if not ips:
            return None
        return sorted(
            ips,
            key=lambda ip: (
                -(facts[ip].events if ip in facts else 0),
                -_ts(facts[ip].last_seen if ip in facts else None).timestamp(),
                address_sort_key(ip),
            ),
        )[0]

    agent_ips = [ip for ip, kind in target.kinds.items() if kind == "agent"]
    if agent_ips:
        return busiest(agent_ips)
    leased = [winning[ip] for ip, kind in target.kinds.items() if kind == "dhcp" and ip in winning]
    newest = _newest_lease(leased)
    if newest is not None:
        return newest.ip
    return busiest([ip for ip, kind in target.kinds.items() if kind != "container"])


def _finish(
    target: _Draft, facts: Mapping[str, AddressFacts], winning: Mapping[str, DhcpLease]
) -> Machine:
    primary = _primary(target, facts, winning)
    ordered = sorted(
        target.kinds.items(),
        key=lambda item: (item[0] != primary, item[1] == "container", address_sort_key(item[0])),
    )
    members = [ip for ip, kind in ordered if kind != "container"]
    names = _names(target, facts, primary, members)
    agent = target.agent
    macs: set[str] = set()
    if agent is not None:
        owned = {m for raw in agent.macs if (m := normalize_mac(raw)) is not None}
        if len(owned) <= MAX_OWNED_MACS:
            macs |= owned
    macs |= {lease.mac for lease in target.leases}
    if target.mac:
        macs.add(target.mac)
    primary_facts = facts.get(primary) if primary else None
    os_name = (agent.os if agent is not None else None) or (
        primary_facts.os if primary_facts is not None else None
    )
    return Machine(
        key=target.key,
        addresses=tuple(MachineAddress(ip=ip, kind=kind) for ip, kind in ordered),
        primary_ip=primary,
        name=names[0].value if names else None,
        name_source=names[0].source if names else None,
        names=tuple(names),
        agent_id=agent.agent_id if agent is not None else None,
        agent_name=agent.name if agent is not None else None,
        agent_last_report=agent.last_report if agent is not None else None,
        os=os_name,
        macs=tuple(sorted(macs)),
        first_seen=_min_dt(*(facts[ip].first_seen for ip in members if ip in facts)),
        last_seen=_max_dt(*(facts[ip].last_seen for ip in members if ip in facts)),
        # The network's events over the members, plus the agent's own documents
        # once. The per-address rows hold the network figure only.
        events=sum(facts[ip].events for ip in members if ip in facts)
        + (agent.docs if agent is not None else 0),
    )


def _names(
    target: _Draft,
    facts: Mapping[str, AddressFacts],
    primary: str | None,
    members: Sequence[str],
) -> list[MachineName]:
    """Every name the machine answers to, strongest source first.

    Declared, then the agent's ``host.name``, then the newest lease hostname,
    then the strong DNS name of the primary address, then the hostname the
    dossier asserts. Each name appears once, under its strongest source.
    """
    candidates: list[tuple[str | None, NameSource]] = []
    ordered = ([primary] if primary else []) + [ip for ip in members if ip != primary]
    for ip in ordered:
        fact = facts.get(ip)
        if fact is not None and fact.declared_name:
            candidates.append((fact.declared_name.strip(), "declared"))
    if target.agent is not None:
        candidates.append((target.agent.name.strip(), "agent"))
    for lease in sorted(target.leases, key=lambda lease: _ts(lease.last_seen), reverse=True):
        candidates.append((_clean_name(lease.hostname, self_reported=True), "dhcp"))
    for ip in ordered:
        fact = facts.get(ip)
        if fact is not None:
            candidates.append((_clean_name(fact.dns_name, self_reported=False), "dns"))
    for ip in ordered:
        fact = facts.get(ip)
        if fact is not None and fact.inferred_name:
            source = _AS_NAME_SOURCE.get(fact.inferred_name_source or "", "other")
            candidates.append((fact.inferred_name.strip(), source))
    out: list[MachineName] = []
    seen: set[str] = set()
    for value, source in candidates:
        if not value or (len(value) < _HOSTNAME_MIN_LEN and source != "declared"):
            continue
        if source != "declared" and is_service_or_reverse_name(value):
            continue
        folded = value.casefold()
        if folded in seen:
            continue
        seen.add(folded)
        out.append(MachineName(value=value, source=source))
    # The name is the strongest source's; within a source, the collection order
    # (primary address first, newest lease first) decides.
    out.sort(key=lambda name: _NAME_SOURCE_RANK.get(name.source, len(NAME_SOURCES)))
    return out


def _merge_prior(
    machines: list[Machine], prior: list[PriorMachine]
) -> tuple[list[Machine], dict[str, str]]:
    """Carry the previous sweep's history onto this sweep's machines.

    A machine with the same key keeps its merges and its first sighting. An
    earlier machine whose key is gone, and whose addresses or MAC now sit in a
    machine with a STRONGER key, merges into it: an ``ip:`` or ``mac:`` machine
    whose agent appeared keeps its history under the ``agent:`` key. A merge is
    never sideways: two MACs are two devices.
    """
    by_key = {m.key: m for m in machines}
    merged: dict[str, str] = {}
    extra_from: dict[str, set[str]] = {m.key: set() for m in machines}
    first_seen: dict[str, datetime | None] = {m.key: m.first_seen for m in machines}
    for old in prior:
        if old.key in by_key:
            extra_from[old.key].update(old.merged_from)
            first_seen[old.key] = _min_dt(first_seen[old.key], old.first_seen)
            continue
        old_ips = {ip for raw in old.addresses if (ip := identity_bearing_ip(raw)) is not None}
        old_macs = {mac for raw in old.macs if (mac := normalize_mac(raw)) is not None}
        if _key_kind(old.key) == "mac":
            held = normalize_mac(old.key.split(":", 1)[1])
            if held is not None:
                old_macs.add(held)
        best: tuple[int, int, str] | None = None
        for machine in machines:
            if _KEY_RANK.get(_key_kind(machine.key), -1) <= _KEY_RANK.get(_key_kind(old.key), -1):
                continue
            overlap = len(old_ips & {a.ip for a in machine.members}) + len(
                old_macs & set(machine.macs)
            )
            if overlap == 0:
                continue
            rank = (overlap, _KEY_RANK.get(_key_kind(machine.key), -1), machine.key)
            if best is None or rank > best:
                best = rank
        if best is None:
            continue
        target = best[2]
        merged[old.key] = target
        extra_from[target].update({old.key, *old.merged_from})
        first_seen[target] = _min_dt(first_seen[target], old.first_seen)
    out = [
        dataclasses.replace(
            machine,
            merged_from=tuple(sorted(extra_from[machine.key] - {machine.key})),
            first_seen=first_seen[machine.key],
        )
        for machine in machines
    ]
    return out, merged


# ---------------------------------------------------------------------------
# Persistence: the sweep's last step
# ---------------------------------------------------------------------------

# How a hostname field's winning evidence line names its signal:
# "pve01 (from dhcp)", "ws-1.lab.internal (from dns, 40 answers ...)".
_SIGNAL_RE = re.compile(r"\(from ([^,)]+)")
_SIGNAL_SOURCE: dict[str, NameSource] = {
    "dhcp": "dhcp",
    "ntlm": "ntlm",
    "smb": "ntlm",
    "dns": "dns",
}


def _inferred_name_source(row: HostDossierField) -> str:
    """The NameSource of a hostname field's inferred winner."""
    if row.inferred_source == "hostlog":
        return "agent"
    evidence = row.inferred_evidence or {}
    lane = evidence.get(row.inferred_source or "") if isinstance(evidence, dict) else None
    strings = lane.get("strings") if isinstance(lane, dict) else None
    if isinstance(strings, list) and strings:
        match = _SIGNAL_RE.search(str(strings[0]))
        if match:
            return _SIGNAL_SOURCE.get(match.group(1).strip(), "other")
    return "other"


async def load_address_facts(
    db: AsyncSession,
    *,
    dns_names: Mapping[str, str] | None = None,
    now: datetime,
    min_confidence: float,
    staleness_hours: int,
) -> list[AddressFacts]:
    """Every census address as :class:`AddressFacts`, read through the resolver.

    The hostname comes through the resolver's gates, so a name the dossier
    would not assert does not name a machine either.
    """
    hosts = (await db.scalars(select(HostDossier))).all()
    rows = (
        await db.scalars(
            select(HostDossierField).where(
                HostDossierField.field.in_(("hostname", "os_detail", "os_family"))
            )
        )
    ).all()
    by_host: dict[int, dict[str, HostDossierField]] = {}
    for row in rows:
        by_host.setdefault(row.dossier_id, {})[row.field] = row
    out: list[AddressFacts] = []
    dns = dns_names or {}
    for host in hosts:
        fields = by_host.get(host.id, {})
        declared: str | None = None
        inferred: str | None = None
        inferred_source: str | None = None
        hostname = fields.get("hostname")
        if hostname is not None:
            if hostname.operator_value:
                declared = hostname.operator_value
            resolved = resolve_field(
                hostname, now=now, min_confidence=min_confidence, staleness_hours=staleness_hours
            )
            if resolved.inference_assertable and hostname.inferred_value:
                inferred = hostname.inferred_value
                inferred_source = _inferred_name_source(hostname)
        os_name: str | None = None
        for name in ("os_detail", "os_family"):
            held = fields.get(name)
            if held is None:
                continue
            resolved = resolve_field(
                held, now=now, min_confidence=min_confidence, staleness_hours=staleness_hours
            )
            if resolved.value:
                os_name = resolved.value
                break
        out.append(
            AddressFacts(
                ip=host.ip,
                events=int(host.event_count or 0),
                first_seen=host.first_seen,
                last_seen=host.last_seen,
                declared_name=declared,
                inferred_name=inferred,
                inferred_name_source=inferred_source,
                dns_name=dns.get(host.ip),
                os=os_name,
            )
        )
    return out


async def load_prior(db: AsyncSession) -> list[PriorMachine]:
    rows = (await db.scalars(select(HostMachine))).all()
    return [
        PriorMachine(
            key=row.machine_key,
            addresses=tuple(
                str(entry.get("ip"))
                for entry in (row.addresses_json or [])
                if isinstance(entry, dict) and entry.get("current") and entry.get("ip")
            ),
            macs=tuple(str(m) for m in (row.macs_json or [])),
            merged_from=tuple(str(k) for k in (row.merged_from_json or [])),
            first_seen=row.first_seen,
        )
        for row in rows
    ]


@dataclass
class PersistStats:
    machines: int = 0
    merged: int = 0
    retired: int = 0
    pruned: int = 0


def _iso(value: datetime | None) -> str | None:
    return _ts(value).isoformat() if value is not None else None


def _history(
    machine: Machine,
    facts: Mapping[str, AddressFacts],
    held: Sequence[Mapping[str, Any]],
) -> list[dict[str, Any]]:
    """The machine's address history: the current addresses, then the earlier ones."""
    current = {a.ip for a in machine.addresses}
    out: list[dict[str, Any]] = []
    for address in machine.addresses:
        fact = facts.get(address.ip)
        earlier = next((e for e in held if e.get("ip") == address.ip), None)
        first = fact.first_seen if fact is not None else None
        if earlier is not None and isinstance(earlier.get("first_seen"), str):
            with contextlib.suppress(ValueError):
                first = _min_dt(first, datetime.fromisoformat(earlier["first_seen"]))
        out.append(
            {
                "ip": address.ip,
                "kind": address.kind,
                "first_seen": _iso(first),
                "last_seen": _iso(fact.last_seen if fact is not None else None),
                "current": True,
            }
        )
    seen = set(current)
    for entry in held:
        ip = entry.get("ip")
        if not isinstance(ip, str) or ip in seen:
            continue
        seen.add(ip)
        out.append({**entry, "current": False})
    return out


def _fill(
    row: HostMachine,
    machine: Machine,
    facts: Mapping[str, AddressFacts],
    held: Sequence[Mapping[str, Any]],
    stamp: datetime,
) -> None:
    """Write one machine onto its row. The history keeps the earlier addresses."""
    row.name = machine.name
    row.name_source = machine.name_source
    row.names_json = [{"value": n.value, "source": n.source} for n in machine.names]
    row.primary_ip = machine.primary_ip
    row.agent_id = machine.agent_id
    row.agent_name = machine.agent_name
    row.agent_last_report = _max_dt(machine.agent_last_report)
    row.os = machine.os
    row.macs_json = list(machine.macs)
    row.first_seen = _min_dt(row.first_seen, machine.first_seen)
    row.last_seen = _max_dt(row.last_seen, machine.last_seen)
    row.event_count = machine.events
    row.address_count = len(machine.members)
    row.container_count = len(machine.containers)
    row.merged_from_json = list(machine.merged_from)
    row.addresses_json = _history(machine, facts, held)
    row.built_at = stamp


async def _retire(
    db: AsyncSession,
    existing: Mapping[str, HostMachine],
    keep: set[str],
    *,
    cutoff: datetime,
    stats: PersistStats,
) -> None:
    """A machine this sweep did not produce stays as history, until it is stale."""
    for key, row in existing.items():
        if key in keep:
            continue
        if _ts(row.last_seen or row.built_at) < cutoff:
            await db.delete(row)
            stats.pruned += 1
            continue
        row.address_count = 0
        row.container_count = 0
        row.event_count = 0
        row.addresses_json = [
            {**entry, "current": False}
            for entry in (row.addresses_json or [])
            if isinstance(entry, dict)
        ]
        stats.retired += 1


async def _point_addresses(
    db: AsyncSession, machines: Sequence[Machine], rows: Mapping[str, HostMachine]
) -> None:
    """Set every address row's machine and kind. One UPDATE per (machine, kind)."""
    await db.execute(
        update(HostDossier)
        .values(machine_id=None, address_kind=None)
        .execution_options(synchronize_session=False)
    )
    for machine in machines:
        row = rows[machine.key]
        by_kind: dict[str, list[str]] = {}
        for address in machine.addresses:
            by_kind.setdefault(address.kind, []).append(address.ip)
        for kind, ips in by_kind.items():
            await db.execute(
                update(HostDossier)
                .where(HostDossier.host_key.in_(ips))
                .values(machine_id=row.id, address_kind=kind)
                .execution_options(synchronize_session=False)
            )


async def persist_clustering(
    db: AsyncSession,
    clustering: Clustering,
    facts: Iterable[AddressFacts],
    *,
    now: datetime,
    stale_days: int = 30,
) -> PersistStats:
    """Write the machines and point every address row at its machine. Commits.

    One transaction: the address rows and the machine rows change together, so
    a reader never sees an address pointing at a machine that does not hold it.
    A machine this sweep did not produce keeps its row as history at 0
    addresses, until it is older than *stale_days*.
    """
    stats = PersistStats()
    stamp = _ts(now)
    by_ip = {fact.ip: fact for fact in facts}
    existing = {row.machine_key: row for row in (await db.scalars(select(HostMachine))).all()}
    produced: dict[str, HostMachine] = {}
    for machine in clustering.machines:
        row = existing.get(machine.key)
        if row is None:
            row = HostMachine(machine_key=machine.key)
            db.add(row)
        held: list[Mapping[str, Any]] = list(row.addresses_json or [])
        for old_key, new_key in clustering.merged.items():
            if new_key == machine.key and old_key in existing:
                held.extend(existing[old_key].addresses_json or [])
        _fill(row, machine, by_ip, held, stamp)
        produced[machine.key] = row
    stats.machines = len(produced)
    for old_key in clustering.merged:
        old = existing.get(old_key)
        if old is not None and old_key not in produced:
            await db.delete(old)
            stats.merged += 1
    await _retire(
        db,
        existing,
        set(produced) | set(clustering.merged),
        cutoff=stamp - timedelta(days=max(1, stale_days)),
        stats=stats,
    )
    await db.flush()
    await _point_addresses(db, clustering.machines, produced)
    await db.commit()
    return stats


# ---------------------------------------------------------------------------
# Reads: membership for the API and the joins
# ---------------------------------------------------------------------------


Matched = Literal["address", "name", "mac", "agent", "key"]


@dataclass(frozen=True)
class Membership:
    """One machine as the joins see it: every address and every name.

    ``addresses`` are the machine's own. Container addresses are listed apart:
    a container's traffic is its own workload, so the joins leave it out.
    """

    key: str
    primary_ip: str | None
    addresses: tuple[str, ...]
    names: tuple[str, ...]
    containers: tuple[str, ...] = ()
    agent_id: str | None = None
    agent_name: str | None = None
    matched: Matched = "address"

    def entity_keys(self, *, label_is_unique: Callable[[str], bool] | None = None) -> list[str]:
        """Every key the machine's observations sit under: addresses and names.

        A short label joins only when *label_is_unique* says no other machine
        answers to it.
        """
        out: dict[str, None] = {}
        for ip in self.addresses:
            out.setdefault(ip, None)
        for name in self.names:
            out.setdefault(name, None)
            label = name.split(".", 1)[0]
            if label and label != name and (label_is_unique is None or label_is_unique(label)):
                out.setdefault(label, None)
        return list(out)


async def _membership(db: AsyncSession, row: HostMachine, matched: Matched) -> Membership:
    held = (
        await db.execute(
            select(HostDossier.ip, HostDossier.address_kind).where(HostDossier.machine_id == row.id)
        )
    ).all()
    addresses = sorted({str(ip) for ip, kind in held if kind != "container"}, key=address_sort_key)
    containers = sorted({str(ip) for ip, kind in held if kind == "container"}, key=address_sort_key)
    if row.primary_ip and row.primary_ip in addresses:
        addresses.remove(row.primary_ip)
        addresses.insert(0, row.primary_ip)
    names: list[str] = []
    for entry in row.names_json or []:
        value = entry.get("value") if isinstance(entry, dict) else None
        if isinstance(value, str) and value and value not in names:
            names.append(value)
    if row.agent_name and row.agent_name not in names:
        names.append(row.agent_name)
    declared = (
        await db.scalars(
            select(HostDossierField.operator_value)
            .join(HostDossier, HostDossier.id == HostDossierField.dossier_id)
            .where(
                HostDossier.machine_id == row.id,
                HostDossierField.field == "hostname",
                HostDossierField.operator_value.is_not(None),
            )
        )
    ).all()
    for value in declared:
        if isinstance(value, str) and value.strip() and value.strip() not in names:
            names.append(value.strip())
    return Membership(
        key=row.machine_key,
        primary_ip=row.primary_ip,
        addresses=tuple(addresses),
        names=tuple(names),
        containers=tuple(containers),
        agent_id=row.agent_id,
        agent_name=row.agent_name,
        matched=matched,
    )


def _is_address(value: str) -> str | None:
    try:
        return str(ipaddress.ip_address(value.strip()))
    except ValueError:
        return None


def _fold(value: str) -> str:
    return value.strip().rstrip(".").casefold()


async def _live_names(db: AsyncSession) -> dict[int, tuple[HostMachine, set[str]]]:
    """Every live machine with the folded names it answers to, declared ones too."""
    rows = (await db.scalars(select(HostMachine).where(HostMachine.address_count > 0))).all()
    out: dict[int, tuple[HostMachine, set[str]]] = {}
    for row in rows:
        names = {
            _fold(str(entry.get("value") or ""))
            for entry in (row.names_json or [])
            if isinstance(entry, dict) and entry.get("value")
        }
        if row.agent_name:
            names.add(_fold(row.agent_name))
        out[row.id] = (row, names)
    declared = (
        await db.execute(
            select(HostDossier.machine_id, HostDossierField.operator_value)
            .join(HostDossierField, HostDossierField.dossier_id == HostDossier.id)
            .where(
                HostDossierField.field == "hostname",
                HostDossierField.operator_value.is_not(None),
                HostDossier.machine_id.is_not(None),
            )
        )
    ).all()
    for machine_id, value in declared:
        if isinstance(value, str) and value.strip() and machine_id in out:
            out[machine_id][1].add(_fold(value))
    return out


async def _machines_named(db: AsyncSession, value: str) -> list[HostMachine]:
    """The live machines that answer to *value*.

    A full name matches a full name. A bare label also matches the first label
    of a full name, and a full name also matches a bare machine name equal to
    its first label: the agent says "depot", the analyst types
    "depot.example.test". A full name never matches another full name by its
    first label alone: "db.alpha" and "db.beta" are two machines.
    """
    folded = _fold(value)
    if not folded:
        return []
    label = short_name(folded)
    live = await _live_names(db)
    exact = [row for row, names in live.values() if folded in names]
    if exact:
        return exact
    if "." in folded:
        return [row for row, names in live.values() if label in names]
    return [row for row, names in live.values() if label in {short_name(n) for n in names}]


async def resolve_membership(db: AsyncSession, value: str) -> Membership | None:
    """The machine *value* names: an address, a machine key, an agent id, a MAC or a name.

    A name that two machines answer to resolves to none: an ambiguous join
    shows one machine's history on another's page. ``None`` when nothing
    matches.
    """
    text = value.strip()
    if not text:
        return None
    ip = _is_address(text)
    if ip is not None:
        row = await db.scalar(
            select(HostMachine)
            .join(HostDossier, HostDossier.machine_id == HostMachine.id)
            .where(HostDossier.host_key == ip)
        )
        return await _membership(db, row, "address") if row is not None else None
    if _key_kind(text) in _KEY_RANK and ":" in text:
        row = await db.scalar(select(HostMachine).where(HostMachine.machine_key == text))
        if row is not None and row.address_count > 0:
            return await _membership(db, row, "key")
    row = await db.scalar(
        select(HostMachine).where(HostMachine.agent_id == text, HostMachine.address_count > 0)
    )
    if row is not None:
        return await _membership(db, row, "agent")
    mac = normalize_mac(text)
    if mac is not None and len(re.sub(r"[^0-9a-fA-F]", "", text)) == 12:
        candidates = (
            await db.scalars(select(HostMachine).where(HostMachine.address_count > 0))
        ).all()
        holders = [row for row in candidates if mac in (row.macs_json or [])]
        if len(holders) == 1:
            return await _membership(db, holders[0], "mac")
        if holders:
            return None
    named = await _machines_named(db, text)
    if len(named) == 1:
        return await _membership(db, named[0], "name")
    return None


async def label_owners(db: AsyncSession) -> dict[str, set[str]]:
    """Short label -> the live machine keys that answer to it."""
    out: dict[str, set[str]] = {}
    for row, names in (await _live_names(db)).values():
        for name in names:
            out.setdefault(short_name(name), set()).add(row.machine_key)
    return out


async def entity_expansion(db: AsyncSession, value: str) -> list[str]:
    """Every key one entity's machine is stored under, *value* first.

    An address or a name of a machine expands to every address and every name
    of that machine. A first label joins only when no other machine answers to
    it. A value that names no machine expands to itself only.
    """
    text = value.strip()
    if not text:
        return []
    membership = await resolve_membership(db, text)
    if membership is None:
        return [text]
    owners = await label_owners(db)

    def unique(label: str) -> bool:
        return owners.get(label.casefold(), set()) <= {membership.key}

    keys = membership.entity_keys(label_is_unique=unique)
    out = [text]
    folded = {text.casefold()}
    for key in keys:
        if key.casefold() not in folded:
            folded.add(key.casefold())
            out.append(key)
    return out
