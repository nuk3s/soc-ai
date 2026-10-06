"""The indexed clustering steps give the machines the scans gave.

``_merge_prior`` scanned every machine for every earlier machine, and the
lease step scanned every lease for every draft. Both were quadratic: the
sweep after 6,783 agents appeared on a 20,000-host estate spent 102 seconds
in the merge alone. The indexed versions must decide exactly what the scans
decided. The scans live here, verbatim, as the reference.

The inputs come from the scale harness's synthetic estate, with planted
ties: an earlier machine whose addresses split evenly between two machines,
an earlier ``mac:`` machine whose MAC an agent now owns, and an earlier
machine that overlaps only a weaker key.
"""

from __future__ import annotations

import dataclasses
from collections.abc import Iterable
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from scripts.scale import estate as estate_mod
from soc_ai.dossier.types import DhcpLease, identity_bearing_ip
from soc_ai.store import host_machines as hm

_NOW = datetime(2026, 10, 4, 12, 0, tzinfo=UTC)


def _scan_merge_prior(
    machines: list[hm.Machine], prior: list[hm.PriorMachine]
) -> tuple[list[hm.Machine], dict[str, str]]:
    """The merge as it was before the index, for the comparison."""
    by_key = {m.key: m for m in machines}
    merged: dict[str, str] = {}
    extra_from: dict[str, set[str]] = {m.key: set() for m in machines}
    first_seen: dict[str, datetime | None] = {m.key: m.first_seen for m in machines}
    for old in prior:
        if old.key in by_key:
            extra_from[old.key].update(old.merged_from)
            first_seen[old.key] = hm._min_dt(first_seen[old.key], old.first_seen)
            continue
        old_ips = {ip for raw in old.addresses if (ip := identity_bearing_ip(raw)) is not None}
        old_macs = {mac for raw in old.macs if (mac := hm.normalize_mac(raw)) is not None}
        if hm._key_kind(old.key) == "mac":
            held = hm.normalize_mac(old.key.split(":", 1)[1])
            if held is not None:
                old_macs.add(held)
        best: tuple[int, int, str] | None = None
        for machine in machines:
            if hm._KEY_RANK.get(hm._key_kind(machine.key), -1) <= hm._KEY_RANK.get(
                hm._key_kind(old.key), -1
            ):
                continue
            overlap = len(old_ips & {a.ip for a in machine.members}) + len(
                old_macs & set(machine.macs)
            )
            if overlap == 0:
                continue
            rank = (overlap, hm._KEY_RANK.get(hm._key_kind(machine.key), -1), machine.key)
            if best is None or rank > best:
                best = rank
        if best is None:
            continue
        target = best[2]
        merged[old.key] = target
        extra_from[target].update({old.key, *old.merged_from})
        first_seen[target] = hm._min_dt(first_seen[target], old.first_seen)
    out = [
        dataclasses.replace(
            machine,
            merged_from=tuple(sorted(extra_from[machine.key] - {machine.key})),
            first_seen=first_seen[machine.key],
        )
        for machine in machines
    ]
    return out, merged


def _scan_place_leases(self: Any, leases: Iterable[DhcpLease]) -> None:
    """Rule 3 as it was before the index, for the comparison."""
    owners: dict[str, set[str]] = {}
    for agent in self.agents:
        macs = {mac for raw in agent.macs if (mac := hm.normalize_mac(raw)) is not None}
        if len(macs) <= hm.MAX_OWNED_MACS:
            for mac in macs:
                owners.setdefault(mac, set()).add(agent.agent_id)
    clean = hm._clean_leases(leases)
    by_ip: dict[str, list[DhcpLease]] = {}
    for lease in clean:
        by_ip.setdefault(lease.ip, []).append(lease)
    for ip, held in by_ip.items():
        newest = hm._newest_lease(held)
        if newest is not None:
            self.winning[ip] = newest
    for ip in sorted(self.winning, key=hm.address_sort_key):
        if not self._free(ip):
            continue
        lease = self.winning[ip]
        mac_owners = owners.get(lease.mac, set())
        if len(mac_owners) == 1:
            self._place(ip, f"agent:{next(iter(mac_owners))}", "dhcp")
        else:
            self._draft(f"mac:{lease.mac}").mac = lease.mac
            self._place(ip, f"mac:{lease.mac}", "dhcp")
    for target in self.drafts.values():
        owned: set[str] = set()
        if target.agent is not None:
            mine = {target.agent.agent_id}
            owned = {mac for mac, ids in owners.items() if ids == mine}
        elif target.mac is not None:
            owned = {target.mac}
        target.leases.extend(lease for lease in clean if lease.mac in owned)


def _inputs(hosts: int) -> dict[str, Any]:
    estate = estate_mod.build(hosts)
    facts: list[hm.AddressFacts] = []
    for h in estate.hosts:
        addresses = [h.ip, *h.extra_ips, *h.containers]
        if h.named_nic:
            addresses.append(h.named_nic)
        for ip in addresses:
            facts.append(
                hm.AddressFacts(
                    ip=ip,
                    events=10 + h.index % 7,
                    first_seen=_NOW - timedelta(days=9),
                    last_seen=_NOW - timedelta(hours=h.index % 50),
                    dns_name=h.dns_name if ip in (h.ip, h.named_nic) else None,
                )
            )
    agents = [
        hm.AgentClaim(
            agent_id=h.agent_id,
            name=h.name,
            os=h.os,
            macs=(h.mac, *h.veth_macs),
            addresses=(h.ip, *h.extra_ips, *((h.bridge, "172.18.0.1") if h.bridge else ())),
            last_report=_NOW,
            docs=10,
        )
        for h in estate.hosts
        if h.agent_id
    ]
    leases = [
        DhcpLease(
            ip=h.ip,
            mac=h.mac,
            hostname=h.name,
            first_seen=_NOW - timedelta(days=9),
            last_seen=_NOW - timedelta(hours=h.index % 13),
        )
        for h in estate.hosts
        if h.leased
    ]
    # Two leases for one address, two MACs: the newer must win either way.
    leased = [h for h in estate.hosts if h.leased]
    leases.append(DhcpLease(ip=leased[0].ip, mac=leased[1].mac, hostname="twin", last_seen=_NOW))
    sightings = [
        hm.ContainerSighting(ip=c, agent_id=h.agent_id or "")
        for h in estate.hosts
        for c in h.containers
    ]
    return {"addresses": facts, "agents": agents, "leases": leases, "sightings": sightings}


def _prior(first: hm.Clustering) -> list[hm.PriorMachine]:
    """The previous sweep: every agent machine was a plain address, plus planted ties."""
    prior = [
        hm.PriorMachine(
            key=f"ip:{m.primary_ip}" if m.key.startswith("agent:") else m.key,
            addresses=tuple(a.ip for a in m.members),
            macs=m.macs,
            first_seen=(m.first_seen or _NOW) - timedelta(days=30),
            merged_from=("ip:192.0.2.250",) if m.key.startswith("agent:") else (),
        )
        for m in first.machines
    ]
    agents = [m for m in first.machines if m.key.startswith("agent:")]
    singles = [m for m in first.machines if m.key.startswith("ip:")]
    # An earlier machine split evenly between an agent and a plain address.
    prior.append(
        hm.PriorMachine(
            key="ip:198.51.100.250",
            addresses=(agents[0].members[0].ip, singles[0].members[0].ip),
        )
    )
    # An earlier MAC machine whose MAC an agent owns now.
    prior.append(hm.PriorMachine(key=f"mac:{agents[1].macs[0]}", addresses=()))
    # An earlier machine that overlaps two agents equally: the key breaks the tie.
    prior.append(
        hm.PriorMachine(
            key="ip:198.51.100.251",
            addresses=(agents[2].members[0].ip, agents[3].members[0].ip),
        )
    )
    return prior


@pytest.mark.parametrize("hosts", [300, 1500])
def test_the_indexed_steps_give_the_machines_the_scans_gave(
    hosts: int, monkeypatch: pytest.MonkeyPatch
) -> None:
    inputs = _inputs(hosts)
    first = hm.cluster_machines(**inputs)
    prior = _prior(first)

    indexed = hm.cluster_machines(**inputs, prior=prior)
    monkeypatch.setattr(hm, "_merge_prior", _scan_merge_prior)
    monkeypatch.setattr(hm._Clusterer, "place_leases", _scan_place_leases)
    scanned = hm.cluster_machines(**inputs, prior=prior)

    assert len(indexed.merged) > 10, "the prior must exercise the merge"
    assert indexed.merged == scanned.merged
    assert indexed.machines == scanned.machines
    assert indexed.shared == scanned.shared
