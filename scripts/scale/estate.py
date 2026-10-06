"""A synthetic estate for the scale harness.

The estate is N hosts, from 1,000 to 20,000, with the features that make the
dossier sweep, the machine clustering and the profile build work hard:

* addresses in 10.100.0.0/14, a few in the RFC 5737 networks 192.0.2.0/24
  and 198.51.100.0/24, and internet peers in 203.0.113.0/24;
* agents on a share of the hosts. Some report two addresses, some own a
  container bridge and report its gateway, and every bridge owner reports one
  shared gateway that belongs to nobody;
* DHCP leases with a MAC and a hostname, DNS names, declared roles on a few;
* containers that an agent's endpoint sensor sees;
* hourly flow counts, served ports, logon users and process names per host,
  repeated over ``days`` baseline days, and a recent day with the planted
  departures.

The estate is data only. :mod:`scripts.scale.grid` answers searches from it.

A row is one document shape with an hourly pattern: ``pattern[h]`` documents
in hour ``h`` of each day in ``days``. Day 0 is the last 24 hours before
``anchor``. Hour ``h`` of day ``d`` starts at ``anchor - (d + 1) * 24 h + h``,
and its documents carry the time 30 minutes into the hour.

Every value is synthetic. No address here belongs to a real network.
"""

from __future__ import annotations

import argparse
import ipaddress
import random
import sys
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

# The estate's own address space, as the operator would configure it.
CIDRS: tuple[str, ...] = ("10.0.0.0/8", "172.16.0.0/12", "192.0.2.0/24", "198.51.100.0/24")
_INTERNET = "203.0.113."
_DOMAIN = "corp.example.test"

# Shares of the estate, by role. The rest are workstations.
_SERVER_SHARE = 0.08
_HYPERVISOR_SHARE = 0.01
_PRINTER_SHARE = 0.03
# Shares of each role with an agent.
_AGENT_SHARE = {"workstation": 0.3, "server": 0.8, "hypervisor": 1.0, "printer": 0.0}
# Of the agents: a second address, a container bridge.
_MULTI_ADDRESS_SHARE = 0.1
_BRIDGE_SHARE_OF_SERVERS = 0.2
# One workstation in five sent nothing for the last three days: leave,
# travel, a laptop in a drawer. The second profile build skips them.
_DORMANT_EVERY = 5
_DORMANT_DAYS = 3
# Leases go to these roles, at this share.
_LEASE_SHARE = {"workstation": 0.6, "printer": 1.0, "server": 0.0, "hypervisor": 0.0}
# The shared default gateway every bridge owner reports. It belongs to nobody.
_SHARED_GATEWAY = "172.18.0.1"

_WORKSTATION_PROCESSES: tuple[tuple[str, str], ...] = (
    ("explorer.exe", "userinit.exe"),
    ("chrome.exe", "explorer.exe"),
    ("svchost.exe", "services.exe"),
    ("onedrive.exe", "explorer.exe"),
)
_SERVER_PROCESSES: tuple[tuple[str, str], ...] = (
    ("sshd", "systemd"),
    ("nginx", "systemd"),
    ("cron", "systemd"),
)
_SERVER_PORTS: tuple[int, ...] = (443, 22, 5432, 8080)


@dataclass
class Host:
    """One device in the estate."""

    index: int
    ip: str
    role: str
    name: str
    mac: str
    agent_id: str | None = None
    extra_ips: tuple[str, ...] = ()
    # An address the agent does not report, with a DNS name that matches the
    # agent's short name. The machine clustering joins it by name.
    named_nic: str | None = None
    bridge: str | None = None
    containers: tuple[str, ...] = ()
    veth_macs: tuple[str, ...] = ()
    leased: bool = False
    dns_name: str | None = None
    declared_role: str | None = None

    @property
    def os(self) -> str:
        return "Windows" if self.role == "workstation" else "Linux"


@dataclass(frozen=True)
class Row:
    """One document shape, repeated by an hourly pattern over a set of days."""

    doc: dict[str, Any]
    pattern: tuple[int, ...]
    days: frozenset[int]


@dataclass
class Estate:
    """The hosts, the rows, and what was planted."""

    hosts: list[Host]
    rows: list[Row]
    anchor: datetime
    days: int
    seed: int
    cidrs: tuple[str, ...] = CIDRS
    planted: dict[str, list[str]] = field(default_factory=dict)

    @property
    def agents(self) -> list[Host]:
        return [h for h in self.hosts if h.agent_id]

    def summary(self) -> dict[str, int]:
        return {
            "hosts": len(self.hosts),
            "agents": len(self.agents),
            "multi_address": sum(1 for h in self.hosts if h.extra_ips),
            "bridges": sum(1 for h in self.hosts if h.bridge),
            "containers": sum(len(h.containers) for h in self.hosts),
            "leases": sum(1 for h in self.hosts if h.leased),
            "dns_names": sum(1 for h in self.hosts if h.dns_name),
            "declared_roles": sum(1 for h in self.hosts if h.declared_role),
            "rows": len(self.rows),
        }


def _address(index: int) -> str:
    """The primary address of host ``index``: 250 hosts per /24 in 10.100.0.0/14."""
    group, offset = divmod(index, 250)
    return f"10.{100 + group // 256}.{group % 256}.{2 + offset}"


def _second_address(index: int) -> str:
    group, offset = divmod(index, 250)
    return f"10.{104 + group // 256}.{group % 256}.{2 + offset}"


def _dmz_address(slot: int) -> str | None:
    """A DMZ address in the RFC 5737 networks, for the first 500 servers."""
    if slot < 250:
        return f"192.0.2.{2 + slot}"
    if slot < 500:
        return f"198.51.100.{2 + slot - 250}"
    return None


def _mac(index: int, salt: int = 0) -> str:
    raw = (salt << 32) | index
    octets = [0x02, (raw >> 32) & 0xFF, (raw >> 24) & 0xFF, (raw >> 16) & 0xFF]
    octets += [(raw >> 8) & 0xFF, raw & 0xFF]
    return ":".join(f"{o:02x}" for o in octets)


def _bridge(slot: int) -> str:
    return f"172.{20 + slot // 256}.{slot % 256}.1"


def dormant(host: Host) -> bool:
    """Whether a host sent nothing for the last :data:`_DORMANT_DAYS` days.

    The burst host is the one workstation the rule never makes dormant.
    """
    return host.role == "workstation" and host.index % _DORMANT_EVERY == 1


def _workday(rng: random.Random) -> tuple[int, ...]:
    start = rng.randint(7, 9)
    end = rng.randint(17, 19)
    return tuple(rng.randint(4, 12) if start <= h < end else 0 for h in range(24))


def _always(rng: random.Random, low: int, high: int) -> tuple[int, ...]:
    return tuple(rng.randint(low, high) for _ in range(24))


def _scaled(pattern: tuple[int, ...], factor: int) -> tuple[int, ...]:
    return tuple(c * factor for c in pattern)


def _flow(
    src: str,
    dst: str,
    port: int,
    *,
    transport: str = "tcp",
    protocol: str | None = None,
) -> dict[str, Any]:
    doc: dict[str, Any] = {
        "event.dataset": "zeek.conn",
        "source.ip": src,
        "destination.ip": dst,
        "destination.port": port,
        "network.transport": transport,
    }
    if protocol:
        doc["network.protocol"] = protocol
    return doc


def _agent_envelope(host: Host) -> dict[str, Any]:
    ips = [host.ip, *host.extra_ips]
    macs = [host.mac, *host.veth_macs]
    if host.bridge:
        ips += [host.bridge, _SHARED_GATEWAY]
    return {
        "host.name": host.name,
        "host.ip": ips,
        "host.mac": macs,
        "host.os.name": host.os,
        "host.os.version": "11" if host.os == "Windows" else "12",
        "host.architecture": "x86_64",
        "agent.id": host.agent_id,
        "agent.type": "filebeat",
        "agent.version": "9.1.0",
    }


def _hosts(n: int, rng: random.Random) -> list[Host]:
    hosts: list[Host] = []
    dmz = 0
    bridges = 0
    for i in range(n):
        draw = rng.random()
        if draw < _SERVER_SHARE:
            role, prefix = "server", "srv"
        elif draw < _SERVER_SHARE + _HYPERVISOR_SHARE:
            role, prefix = "hypervisor", "hv"
        elif draw < _SERVER_SHARE + _HYPERVISOR_SHARE + _PRINTER_SHARE:
            role, prefix = "printer", "prn"
        else:
            role, prefix = "workstation", "ws"
        ip = _address(i)
        if role == "server" and rng.random() < 0.1:
            moved = _dmz_address(dmz)
            if moved is not None:
                ip = moved
                dmz += 1
        host = Host(index=i, ip=ip, role=role, name=f"{prefix}-{i:06d}", mac=_mac(i))
        if rng.random() < _AGENT_SHARE[role]:
            host.agent_id = f"agent-{i:06d}"
            pick = rng.random()
            if pick < _MULTI_ADDRESS_SHARE:
                host.extra_ips = (_second_address(i),)
            elif pick < 2 * _MULTI_ADDRESS_SHARE:
                host.named_nic = _second_address(i)
            if role == "server" and rng.random() < _BRIDGE_SHARE_OF_SERVERS:
                host.bridge = _bridge(bridges)
                base = host.bridge.rsplit(".", 1)[0]
                host.containers = tuple(f"{base}.{k}" for k in range(2, 5))
                if bridges % 10 == 0:
                    # A container host with a veth MAC per container pair owns
                    # no MAC at all. Twelve is over the clustering's cap of 8.
                    host.veth_macs = tuple(_mac(i, salt=k + 1) for k in range(12))
                bridges += 1
        host.leased = rng.random() < _LEASE_SHARE[role]
        if role in ("server", "hypervisor", "printer") or host.named_nic:
            host.dns_name = f"{host.name}.{_DOMAIN}"
        if role == "hypervisor":
            host.declared_role = "hypervisor"
        elif role == "server" and i % 50 == 0:
            host.declared_role = "server"
        hosts.append(host)
    return hosts


def _rows(  # noqa: PLR0915 - one generator, read top to bottom
    hosts: list[Host], rng: random.Random, days: int
) -> tuple[list[Row], dict[str, list[str]]]:
    baseline = frozenset(range(1, days + 1))
    every = frozenset(range(days + 1))
    recent = frozenset({0})
    servers = [h for h in hosts if h.role == "server"] or hosts[:1]
    printers = [h for h in hosts if h.role == "printer"]
    hypervisors = [h for h in hosts if h.role == "hypervisor"]
    resolver = servers[0]
    rows: list[Row] = []

    # The planted departures, on day 0 only.
    workstations = [h for h in hosts if h.role == "workstation"] or hosts[:1]
    burst = workstations[len(workstations) // 3]
    quiet = [s for s in servers if s is not resolver] or [h for h in hosts if h is not resolver]
    silent = quiet[len(quiet) // 2] if quiet else resolver
    novel = hypervisors[0] if hypervisors else servers[-1]
    planted = {
        "burst_and_night": [burst.ip],
        "silent": [silent.ip],
        "novel_served_port": [novel.ip],
    }

    def add(doc: dict[str, Any], pattern: tuple[int, ...], on: frozenset[int]) -> None:
        if any(pattern) and on:
            rows.append(Row(doc=doc, pattern=pattern, days=on))

    for host in hosts:
        on = baseline if host is silent else every
        if host is not burst and dormant(host):
            on = frozenset(range(_DORMANT_DAYS, days + 1))
        if host.role == "workstation":
            day = _workday(rng)
            server = servers[host.index % len(servers)]
            if host is burst:
                # Day 0: twenty times the volume, at night.
                # Day 0: twenty times the volume, and activity at night.
                night = tuple(40 if h < 6 or h > 22 else 0 for h in range(24))
                add(_flow(host.ip, server.ip, 443), day, baseline)
                add(_flow(host.ip, server.ip, 443), _scaled(day, 20), recent)
                add(_flow(host.ip, server.ip, 443), night, recent)
            else:
                add(_flow(host.ip, server.ip, 443), day, on)
            add(_flow(host.ip, f"{_INTERNET}{2 + host.index % 250}", 443), day, on)
            add(
                _flow(host.ip, resolver.ip, 53, transport="udp", protocol="dns"),
                _scaled(day, 2),
                on,
            )
            if printers and host.index % 20 == 0:
                printer = printers[host.index % len(printers)]
                add(_flow(host.ip, printer.ip, 9100), tuple(min(c, 2) for c in day), on)
            if hypervisors and host.index % 97 == 0:
                hv = hypervisors[host.index % len(hypervisors)]
                add(_flow(host.ip, hv.ip, 8006), day, on)
                add(_flow(host.ip, hv.ip, 22), tuple(min(c, 1) for c in day), on)
            dns_day = tuple(min(c, 3) for c in day)
            add(
                {
                    "event.dataset": "zeek.dns",
                    "source.ip": host.ip,
                    "destination.ip": resolver.ip,
                    "dns.query.name": "intranet.example.test",
                },
                dns_day,
                on,
            )
        else:
            # A steady service load. The rate baseline needs a narrow spread
            # for a collapse to stand out.
            day = _always(rng, 20, 24)
            add(_flow(host.ip, f"{_INTERNET}{2 + host.index % 250}", 443), day, on)
            add(
                _flow(host.ip, f"{_INTERNET}{2 + (host.index + 7) % 250}", 123, transport="udp"),
                tuple(1 if h % 6 == 0 else 0 for h in range(24)),
                on,
            )

        # A DNS name the network's answers agree on, for the census and rule 4.
        if host.dns_name:
            target = host.named_nic or host.ip
            add(
                {
                    "event.dataset": "zeek.dns",
                    "source.ip": resolver.ip,
                    "destination.ip": resolver.ip,
                    "dns.query.name": host.dns_name,
                    "dns.resolved_ip": target,
                },
                tuple(1 if h % 4 == 0 else 0 for h in range(24)),
                every,
            )
        if host.named_nic:
            add(
                _flow(host.named_nic, resolver.ip, 443),
                tuple(1 if h == 12 else 0 for h in range(24)),
                every,
            )

        if host.leased:
            add(
                {
                    "event.dataset": "zeek.dhcp",
                    "host.mac": host.mac,
                    "dhcp.assigned_ip": host.ip,
                    "client.address": host.ip,
                    "host.hostname": host.name,
                },
                tuple(1 if h == 8 else 0 for h in range(24)),
                every,
            )

        if host.agent_id:
            envelope = _agent_envelope(host)
            active = _workday(rng) if host.role == "workstation" else _always(rng, 1, 2)
            if host.role == "workstation":
                add(
                    {
                        **envelope,
                        "event.dataset": "system.security",
                        "event.outcome": "success",
                        "user.name": f"user{host.index:06d}",
                    },
                    tuple(min(c, 2) for c in active),
                    on,
                )
                processes = _WORKSTATION_PROCESSES
                process_dataset = "windows.sysmon_operational"
            else:
                for user in ("admin", "deploy"):
                    add(
                        {
                            **envelope,
                            "event.dataset": "system.auth",
                            "event.outcome": "success",
                            "user.name": user,
                        },
                        tuple(1 if h % 8 == 0 else 0 for h in range(24)),
                        on,
                    )
                processes = _SERVER_PROCESSES
                process_dataset = "endpoint.events.process"
            for name, parent in processes:
                add(
                    {
                        **envelope,
                        "event.dataset": process_dataset,
                        "process.name": name,
                        "process.parent.name": parent,
                    },
                    active,
                    on,
                )
            for container in host.containers:
                add(
                    {
                        **envelope,
                        "event.dataset": "endpoint.events.network",
                        "event.action": "connection_attempted",
                        "source.ip": container,
                        "destination.ip": f"{_INTERNET}{2 + host.index % 250}",
                        "destination.port": 443,
                        "network.transport": "tcp",
                    },
                    _always(rng, 1, 2),
                    on,
                )

    # Day 0: three clients reach the planted host on a port no host serves.
    # A served port is the destination side of a flow, so these rows are the
    # departure.
    clients = [h for h in workstations if h is not burst and not dormant(h)][:3]
    for client in clients:
        add(
            _flow(client.ip, novel.ip, 4444),
            tuple(2 if 9 <= h < 12 else 0 for h in range(24)),
            recent,
        )
    return rows, planted


def build(n: int, *, days: int = 8, seed: int = 20261004, anchor: datetime | None = None) -> Estate:
    """Generate the estate. The same ``n``, ``days`` and ``seed`` give the same estate."""
    if n < 1:
        raise ValueError("an estate holds at least one host")
    rng = random.Random(seed)
    hosts = _hosts(n, rng)
    rows, planted = _rows(hosts, rng, days)
    return Estate(
        hosts=hosts,
        rows=rows,
        anchor=anchor or datetime.now(UTC),
        days=days,
        seed=seed,
        planted=planted,
    )


def internal(ip: str) -> bool:
    """Whether an address sits in the estate's CIDRs."""
    address = ipaddress.ip_address(ip)
    return any(address in ipaddress.ip_network(c) for c in CIDRS)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Generate a synthetic estate and print its size.")
    parser.add_argument("--hosts", type=int, default=2000)
    parser.add_argument("--days", type=int, default=8)
    parser.add_argument("--seed", type=int, default=20261004)
    args = parser.parse_args(argv)
    estate = build(args.hosts, days=args.days, seed=args.seed)
    for key, value in estate.summary().items():
        print(f"{key:>16}: {value}")
    for kind, ips in sorted(estate.planted.items()):
        print(f"{'planted ' + kind:>16}: {', '.join(ips)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
