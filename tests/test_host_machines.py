"""Tests for the machine clustering (``soc_ai.store.host_machines``).

One row per machine on the Hosts screen. The clustering is a pure function, so
every rule is tested here from hand-built input shaped like the production
census of 2026-10-02: an agent with fourteen addresses, a container host with
349 MACs, a DHCP address leased to two devices in one window, a Docker bridge
gateway on three hosts. The identifiers are test values (RFC 5737, 10.0.0.0/8,
example.test).

The negative controls sit on the path each guard would MISS: the shared bridge
merges two machines only if the shared address is allowed to join, the 349-MAC
host absorbs DHCP devices only if MAC ownership has no ceiling, and so on.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from soc_ai.store.host_machines import (
    MAX_OWNED_MACS,
    AddressFacts,
    AgentClaim,
    ContainerSighting,
    DhcpLease,
    Machine,
    PriorMachine,
    address_sort_key,
    cluster_machines,
    normalize_mac,
    short_name,
)

_T0 = datetime(2026, 9, 20, 8, 0, tzinfo=UTC)


def _t(hours: int) -> datetime:
    return _T0 + timedelta(hours=hours)


def _facts(*ips: str, events: int = 10, **extra: Any) -> list[AddressFacts]:
    return [
        AddressFacts(ip=ip, events=events, first_seen=_t(0), last_seen=_t(1), **extra) for ip in ips
    ]


def _by_key(machines: tuple[Machine, ...]) -> dict[str, Machine]:
    return {m.key: m for m in machines}


def _owner(machines: tuple[Machine, ...], ip: str) -> Machine:
    held = [m for m in machines if ip in {a.ip for a in m.addresses}]
    assert len(held) == 1, f"{ip} sits in {len(held)} machines"
    return held[0]


def _kind(machine: Machine, ip: str) -> str:
    return next(a.kind for a in machine.addresses if a.ip == ip)


# ---------------------------------------------------------------------------
# Rule 1: agent
# ---------------------------------------------------------------------------

_PROXY = AgentClaim(
    agent_id="a-proxy",
    name="proxy",
    os="Debian GNU/Linux 13",
    macs=("52-54-00-00-00-01",),
    addresses=(
        "10.40.0.119",
        "10.41.99.1",
        "10.42.1.5",
        *(f"10.43.{i}.1" for i in range(1, 12)),
        "fe80::5054:ff:fe00:1",
    ),
    last_report=_t(5),
)


def test_one_agent_is_one_machine_with_every_address_it_reports() -> None:
    ips = [a for a in _PROXY.addresses if not a.startswith("fe80")]
    facts = [
        AddressFacts(ip=ip, events=9000 if ip == "10.40.0.119" else 3, last_seen=_t(2))
        for ip in ips
    ]

    result = cluster_machines(facts, agents=[_PROXY])

    assert len(result.machines) == 1
    machine = result.machines[0]
    assert machine.key == "agent:a-proxy"
    assert {a.ip for a in machine.addresses} == set(ips)
    assert {a.kind for a in machine.addresses} == {"agent"}
    assert machine.primary_ip == "10.40.0.119"
    assert machine.addresses[0].ip == "10.40.0.119"
    assert (machine.name, machine.name_source) == ("proxy", "agent")
    assert machine.agent_name == "proxy"
    assert machine.os == "Debian GNU/Linux 13"
    assert machine.events == 9000 + 3 * (len(ips) - 1)


def test_an_agent_named_after_a_gtld_names_its_machine() -> None:
    agent = AgentClaim(agent_id="a-h", name="nexus", addresses=("10.40.0.129",))

    machine = cluster_machines(_facts("10.40.0.129"), agents=[agent]).machines[0]

    assert (machine.name, machine.name_source) == ("nexus", "agent")


def test_two_agents_that_share_a_bridge_gateway_do_not_merge() -> None:
    """NEGATIVE CONTROL: 172.17.0.1 is on every Docker host.

    Two agents report it. If the shared address joined either, the next rule to
    read "the machine of 172.17.0.1" would fold the two hosts together.
    """
    runner = AgentClaim(
        agent_id="a-runner", name="build-runner", addresses=("10.40.0.172", "172.17.0.1")
    )
    registry = AgentClaim(agent_id="a-reg", name="registry", addresses=("10.40.0.75", "172.17.0.1"))

    result = cluster_machines(
        _facts("10.40.0.172", "10.40.0.75", "172.17.0.1"), agents=[runner, registry]
    )

    machines = _by_key(result.machines)
    assert {a.ip for a in machines["agent:a-runner"].addresses} == {"10.40.0.172"}
    assert {a.ip for a in machines["agent:a-reg"].addresses} == {"10.40.0.75"}
    assert result.shared == ("172.17.0.1",)
    bridge = _owner(result.machines, "172.17.0.1")
    assert bridge.key == "ip:172.17.0.1"
    assert bridge.agent_id is None


def test_an_agent_address_outside_the_census_is_not_placed() -> None:
    agent = AgentClaim(agent_id="a-1", name="edge", addresses=("10.40.0.9", "198.51.100.9"))

    machine = cluster_machines(_facts("10.40.0.9"), agents=[agent]).machines[0]

    assert [a.ip for a in machine.addresses] == ["10.40.0.9"]


def test_link_local_addresses_never_join() -> None:
    agent = AgentClaim(
        agent_id="a-1", name="edge", addresses=("10.40.0.9", "fe80::1", "169.254.3.4")
    )

    result = cluster_machines(_facts("10.40.0.9", "169.254.3.4"), agents=[agent])

    assert {a.ip for a in result.machines[0].addresses} == {"10.40.0.9"}


# ---------------------------------------------------------------------------
# Rule 2: bridge and container
# ---------------------------------------------------------------------------

_DEPOT = AgentClaim(
    agent_id="a-depot",
    name="depot",
    addresses=("10.40.0.75", "172.18.0.1", "172.17.0.1"),
)


def test_an_address_only_the_agents_sensor_sees_in_its_bridge_is_a_container() -> None:
    result = cluster_machines(
        _facts("10.40.0.75", "172.18.0.1", "172.18.0.7"),
        agents=[_DEPOT],
        sightings=[ContainerSighting(ip="172.18.0.7", agent_id="a-depot")],
    )

    assert len(result.machines) == 1
    machine = result.machines[0]
    assert _kind(machine, "172.18.0.7") == "container"
    assert [a.ip for a in machine.containers] == ["172.18.0.7"]
    assert "172.18.0.7" not in {a.ip for a in machine.members}
    # A container is no machine row and adds nothing to the machine's activity.
    assert machine.events == 20


def test_a_container_on_a_shared_bridge_goes_to_the_agent_that_sees_it() -> None:
    other = AgentClaim(agent_id="a-other", name="other", addresses=("10.40.0.80", "172.17.0.1"))

    result = cluster_machines(
        _facts("10.40.0.75", "10.40.0.80", "172.17.0.5"),
        agents=[_DEPOT, other],
        sightings=[ContainerSighting(ip="172.17.0.5", agent_id="a-depot")],
    )

    machines = _by_key(result.machines)
    assert _kind(machines["agent:a-depot"], "172.17.0.5") == "container"
    assert "172.17.0.5" not in {a.ip for a in machines["agent:a-other"].addresses}


def test_an_unsighted_address_in_a_bridge_is_not_a_container() -> None:
    """NEGATIVE CONTROL: the agent's endpoint sensor never saw it."""
    result = cluster_machines(_facts("10.40.0.75", "172.18.0.9"), agents=[_DEPOT])

    assert _owner(result.machines, "172.18.0.9").key == "ip:172.18.0.9"


def test_a_sighting_outside_the_agents_bridges_is_not_a_container() -> None:
    """NEGATIVE CONTROL: a peer the endpoint sensor sees on a real LAN."""
    result = cluster_machines(
        _facts("10.40.0.75", "10.40.7.33"),
        agents=[_DEPOT],
        sightings=[ContainerSighting(ip="10.40.7.33", agent_id="a-depot")],
    )

    assert _owner(result.machines, "10.40.7.33").key == "ip:10.40.7.33"


def test_a_sighted_address_in_the_bridge_with_a_lease_stays_a_machine() -> None:
    """NEGATIVE CONTROL: a DHCP lease names the address, so it is a device.

    The builder now sends a sighting whatever other datasets saw the address.
    The lease must still win over the bridge.
    """
    lease = DhcpLease(ip="172.18.0.7", mac="02:00:5e:10:00:31", hostname="cam-3", last_seen=_t(1))

    result = cluster_machines(
        _facts("10.40.0.75", "172.18.0.1", "172.18.0.7"),
        agents=[_DEPOT],
        leases=[lease],
        sightings=[ContainerSighting(ip="172.18.0.7", agent_id="a-depot")],
    )

    machine = _owner(result.machines, "172.18.0.7")
    assert machine.key == "mac:02:00:5e:10:00:31"
    assert _kind(machine, "172.18.0.7") == "dhcp"
    assert _by_key(result.machines)["agent:a-depot"].containers == ()


def test_a_sighted_address_two_agents_hold_in_a_bridge_is_no_container() -> None:
    """NEGATIVE CONTROL: two Docker hosts each own 172.17.0.0/24.

    Both endpoint sensors see 172.17.0.5. Each host may run its own container
    on that address, so neither claim wins.
    """
    other = AgentClaim(agent_id="a-other", name="other", addresses=("10.40.0.80", "172.17.0.1"))

    result = cluster_machines(
        _facts("10.40.0.75", "10.40.0.80", "172.17.0.5"),
        agents=[_DEPOT, other],
        sightings=[
            ContainerSighting(ip="172.17.0.5", agent_id="a-depot"),
            ContainerSighting(ip="172.17.0.5", agent_id="a-other"),
        ],
    )

    assert _owner(result.machines, "172.17.0.5").key == "ip:172.17.0.5"


# ---------------------------------------------------------------------------
# Rule 3: DHCP lease
# ---------------------------------------------------------------------------


def test_a_dhcp_address_with_a_mac_no_agent_owns_is_a_machine_of_its_own() -> None:
    lease = DhcpLease(
        ip="10.50.1.135", mac="02:00:5E:10:00:27", hostname="sensor-view", last_seen=_t(3)
    )

    result = cluster_machines(_facts("10.50.1.135"), leases=[lease])

    machine = result.machines[0]
    assert machine.key == "mac:02:00:5e:10:00:27"
    assert _kind(machine, "10.50.1.135") == "dhcp"
    assert (machine.name, machine.name_source) == ("sensor-view", "dhcp")
    assert machine.macs == ("02:00:5e:10:00:27",)


def test_a_mac_that_moved_between_addresses_is_one_machine() -> None:
    mac = "aa:bb:cc:00:00:05"
    leases = [
        DhcpLease(ip="10.50.1.20", mac=mac, hostname="phone-a", last_seen=_t(1)),
        DhcpLease(ip="10.50.1.21", mac=mac, hostname="phone-a", last_seen=_t(30)),
        DhcpLease(ip="10.50.1.22", mac=mac, hostname="phone-a", last_seen=_t(9)),
    ]

    result = cluster_machines(_facts("10.50.1.20", "10.50.1.21", "10.50.1.22"), leases=leases)

    assert len(result.machines) == 1
    machine = result.machines[0]
    assert machine.primary_ip == "10.50.1.21", "the newest lease is the primary address"
    assert {a.ip for a in machine.addresses} == {"10.50.1.20", "10.50.1.21", "10.50.1.22"}


def test_an_address_leased_to_two_macs_goes_to_the_newer_lease() -> None:
    """NEGATIVE CONTROL: production had one address leased to two devices.

    The older lease must not keep the address, or two machines would share it.
    """
    leases = [
        DhcpLease(
            ip="10.50.1.228", mac="aa:bb:cc:00:00:01", hostname="old-tablet", last_seen=_t(1)
        ),
        DhcpLease(
            ip="10.50.1.228", mac="aa:bb:cc:00:00:02", hostname="new-laptop", last_seen=_t(40)
        ),
        DhcpLease(
            ip="10.50.1.229", mac="aa:bb:cc:00:00:01", hostname="old-tablet", last_seen=_t(41)
        ),
    ]

    result = cluster_machines(_facts("10.50.1.228", "10.50.1.229"), leases=leases)

    machines = _by_key(result.machines)
    assert {a.ip for a in machines["mac:aa:bb:cc:00:00:02"].addresses} == {"10.50.1.228"}
    assert {a.ip for a in machines["mac:aa:bb:cc:00:00:01"].addresses} == {"10.50.1.229"}


def test_a_dhcp_address_joins_the_agent_that_owns_its_mac() -> None:
    agent = AgentClaim(
        agent_id="a-tv",
        name="media-tv",
        macs=("02-00-5E-10-00-41", "02-00-5E-10-00-42", "02-00-5E-10-00-43"),
        addresses=("10.40.0.71",),
    )
    lease = DhcpLease(
        ip="10.50.1.44", mac="02:00:5e:10:00:42", hostname="media-tv", last_seen=_t(2)
    )

    result = cluster_machines(_facts("10.40.0.71", "10.50.1.44"), agents=[agent], leases=[lease])

    assert len(result.machines) == 1
    machine = result.machines[0]
    assert machine.key == "agent:a-tv"
    assert _kind(machine, "10.50.1.44") == "dhcp"
    assert machine.primary_ip == "10.40.0.71", "an agent address outranks a lease"


def test_an_agent_with_349_macs_does_not_absorb_dhcp_devices() -> None:
    """NEGATIVE CONTROL: a container host reports a MAC per veth pair.

    One production agent reported 349. Every DHCP device whose MAC sat in that
    list would join it if MAC ownership had no ceiling.
    """
    macs = tuple(f"02:42:ac:11:{i // 256:02x}:{i % 256:02x}" for i in range(349))
    runner = AgentClaim(
        agent_id="a-runner", name="build-runner", macs=macs, addresses=("10.40.0.172",)
    )
    lease = DhcpLease(ip="10.50.1.90", mac=macs[17], hostname="printer", last_seen=_t(2))

    result = cluster_machines(_facts("10.40.0.172", "10.50.1.90"), agents=[runner], leases=[lease])

    machines = _by_key(result.machines)
    assert {a.ip for a in machines["agent:a-runner"].addresses} == {"10.40.0.172"}
    assert _owner(result.machines, "10.50.1.90").key == f"mac:{macs[17]}"
    # The veth list is not the machine's hardware address either.
    assert machines["agent:a-runner"].macs == ()


def test_the_mac_ceiling_is_eight() -> None:
    macs = tuple(f"02:00:00:00:00:{i:02x}" for i in range(1, MAX_OWNED_MACS + 1))
    agent = AgentClaim(agent_id="a-1", name="box", macs=macs, addresses=("10.40.0.5",))
    lease = DhcpLease(ip="10.50.1.6", mac=macs[0], last_seen=_t(1))

    result = cluster_machines(_facts("10.40.0.5", "10.50.1.6"), agents=[agent], leases=[lease])

    assert _owner(result.machines, "10.50.1.6").key == "agent:a-1"


def test_a_mac_two_agents_report_is_owned_by_neither() -> None:
    a = AgentClaim(
        agent_id="a-1", name="one", macs=("02:00:00:00:00:01",), addresses=("10.40.0.5",)
    )
    b = AgentClaim(
        agent_id="a-2", name="two", macs=("02:00:00:00:00:01",), addresses=("10.40.0.6",)
    )
    lease = DhcpLease(ip="10.50.1.6", mac="02:00:00:00:00:01", last_seen=_t(1))

    result = cluster_machines(
        _facts("10.40.0.5", "10.40.0.6", "10.50.1.6"), agents=[a, b], leases=[lease]
    )

    assert _owner(result.machines, "10.50.1.6").key == "mac:02:00:00:00:00:01"


def test_an_agent_address_keeps_its_agent_whatever_its_lease_says() -> None:
    """A rule never moves an address a stronger rule placed."""
    agent = AgentClaim(agent_id="a-1", name="box", addresses=("10.50.1.7",))
    lease = DhcpLease(
        ip="10.50.1.7", mac="aa:bb:cc:00:00:09", hostname="someone-else", last_seen=_t(9)
    )

    result = cluster_machines(_facts("10.50.1.7"), agents=[agent], leases=[lease])

    assert len(result.machines) == 1
    assert result.machines[0].key == "agent:a-1"
    assert _kind(result.machines[0], "10.50.1.7") == "agent"


# ---------------------------------------------------------------------------
# Rule 4: unique name
# ---------------------------------------------------------------------------


def test_a_network_address_whose_dns_name_matches_one_agent_joins_it() -> None:
    agent = AgentClaim(agent_id="a-h", name="nexus", addresses=("10.40.0.129",))
    facts = [
        *_facts("10.40.0.129"),
        AddressFacts(ip="10.40.3.129", events=4, dns_name="Nexus.example.test"),
    ]

    result = cluster_machines(facts, agents=[agent])

    assert len(result.machines) == 1
    assert _kind(result.machines[0], "10.40.3.129") == "name"


def test_a_dns_name_two_machines_share_joins_neither() -> None:
    """NEGATIVE CONTROL: two agents both call themselves "web"."""
    alpha = AgentClaim(agent_id="a-alpha", name="web", addresses=("10.40.0.10",))
    beta = AgentClaim(agent_id="a-beta", name="web", addresses=("10.40.0.11",))
    facts = [
        *_facts("10.40.0.10", "10.40.0.11"),
        AddressFacts(ip="10.40.3.12", events=4, dns_name="web.example.test"),
    ]

    result = cluster_machines(facts, agents=[alpha, beta])

    assert _owner(result.machines, "10.40.3.12").key == "ip:10.40.3.12"


def test_a_dns_name_an_agent_and_a_dhcp_device_share_joins_neither() -> None:
    agent = AgentClaim(agent_id="a-1", name="kiosk", addresses=("10.40.0.10",))
    lease = DhcpLease(ip="10.50.1.5", mac="aa:bb:cc:00:00:01", hostname="kiosk", last_seen=_t(1))
    facts = [
        *_facts("10.40.0.10", "10.50.1.5"),
        AddressFacts(ip="10.40.3.12", events=4, dns_name="kiosk.example.test"),
    ]

    result = cluster_machines(facts, agents=[agent], leases=[lease])

    assert _owner(result.machines, "10.40.3.12").key == "ip:10.40.3.12"


def test_a_dns_name_matching_only_a_dhcp_device_does_not_join_it() -> None:
    lease = DhcpLease(ip="10.50.1.5", mac="aa:bb:cc:00:00:01", hostname="kiosk", last_seen=_t(1))
    facts = [
        *_facts("10.50.1.5"),
        AddressFacts(ip="10.40.3.12", events=4, dns_name="kiosk.example.test"),
    ]

    result = cluster_machines(facts, leases=[lease])

    assert _owner(result.machines, "10.40.3.12").key == "ip:10.40.3.12"


# ---------------------------------------------------------------------------
# Rule 5: single address
# ---------------------------------------------------------------------------


def test_a_network_only_address_with_no_lease_stays_its_own_machine() -> None:
    """NEGATIVE CONTROL: nothing ties it to anything, so nothing may."""
    agent = AgentClaim(
        agent_id="a-1", name="box", macs=("aa:bb:cc:00:00:01",), addresses=("10.40.0.5",)
    )
    lease = DhcpLease(ip="10.50.1.5", mac="aa:bb:cc:00:00:02", last_seen=_t(1))

    result = cluster_machines(
        _facts("10.40.0.5", "10.50.1.5", "10.60.0.9"), agents=[agent], leases=[lease]
    )

    machine = _owner(result.machines, "10.60.0.9")
    assert machine.key == "ip:10.60.0.9"
    assert [a.kind for a in machine.addresses] == ["network"]
    assert machine.primary_ip == "10.60.0.9"
    assert machine.name is None


# ---------------------------------------------------------------------------
# Key, name and primary address
# ---------------------------------------------------------------------------


def test_keys_are_stable_across_runs() -> None:
    lease = DhcpLease(ip="10.50.1.5", mac="AA-BB-CC-00-00-01", last_seen=_t(1))
    args: dict[str, Any] = {
        "addresses": _facts("10.40.0.119", "10.50.1.5", "10.60.0.9"),
        "agents": [_PROXY],
        "leases": [lease],
    }

    first = cluster_machines(**args)
    second = cluster_machines(**args)

    assert [m.key for m in first.machines] == [m.key for m in second.machines]
    assert {m.key for m in first.machines} == {
        "agent:a-proxy",
        "mac:aa:bb:cc:00:00:01",
        "ip:10.60.0.9",
    }


def test_the_name_comes_from_the_strongest_source() -> None:
    agent = AgentClaim(agent_id="a-1", name="box-agent", addresses=("10.40.0.5",))
    facts = [
        AddressFacts(
            ip="10.40.0.5",
            events=5,
            declared_name="Payroll DB",
            dns_name="box-dns.example.test",
            inferred_name="BOX-NTLM",
            inferred_name_source="ntlm",
        )
    ]

    declared = cluster_machines(facts, agents=[agent]).machines[0]
    assert (declared.name, declared.name_source) == ("Payroll DB", "declared")
    assert [(n.value, n.source) for n in declared.names] == [
        ("Payroll DB", "declared"),
        ("box-agent", "agent"),
        ("box-dns.example.test", "dns"),
        ("BOX-NTLM", "ntlm"),
    ]

    undeclared = [AddressFacts(ip="10.40.0.5", events=5, dns_name="box-dns.example.test")]
    assert cluster_machines(undeclared, agents=[agent]).machines[0].name_source == "agent"

    lease = DhcpLease(
        ip="10.50.1.5", mac="aa:bb:cc:00:00:01", hostname="lease-name", last_seen=_t(1)
    )
    leased = [AddressFacts(ip="10.50.1.5", events=5, dns_name="lease-dns.example.test")]
    machine = cluster_machines(leased, leases=[lease]).machines[0]
    assert (machine.name, machine.name_source) == ("lease-name", "dhcp")

    dns_only = [AddressFacts(ip="10.60.0.9", events=5, dns_name="quiet.example.test")]
    machine = cluster_machines(dns_only).machines[0]
    assert (machine.name, machine.name_source) == ("quiet.example.test", "dns")


def test_a_dns_bare_label_that_is_a_gtld_does_not_name_a_machine() -> None:
    machine = cluster_machines([AddressFacts(ip="10.60.0.9", dns_name="museum")]).machines[0]

    assert machine.name is None


def test_a_reverse_or_service_name_never_names_a_machine() -> None:
    lease = DhcpLease(
        ip="10.50.1.5", mac="aa:bb:cc:00:00:01", hostname="_uscan._tcp.local", last_seen=_t(1)
    )

    machine = cluster_machines(_facts("10.50.1.5"), leases=[lease]).machines[0]

    assert machine.name is None


def test_the_primary_address_is_the_busiest_agent_address() -> None:
    agent = AgentClaim(agent_id="a-1", name="box", addresses=("10.40.0.5", "10.40.0.6"))
    facts = [AddressFacts(ip="10.40.0.5", events=3), AddressFacts(ip="10.40.0.6", events=300)]

    machine = cluster_machines(facts, agents=[agent]).machines[0]

    assert machine.primary_ip == "10.40.0.6"
    assert [a.ip for a in machine.addresses] == ["10.40.0.6", "10.40.0.5"]


def test_activity_is_the_sum_and_the_newest_sighting_of_the_addresses() -> None:
    agent = AgentClaim(agent_id="a-1", name="box", addresses=("10.40.0.5", "10.40.0.6"))
    facts = [
        AddressFacts(ip="10.40.0.5", events=3, first_seen=_t(-50), last_seen=_t(2)),
        AddressFacts(ip="10.40.0.6", events=300, first_seen=_t(-5), last_seen=_t(20)),
    ]

    machine = cluster_machines(facts, agents=[agent]).machines[0]

    assert machine.events == 303
    assert machine.first_seen == _t(-50).replace(tzinfo=None)
    assert machine.last_seen == _t(20).replace(tzinfo=None)


# ---------------------------------------------------------------------------
# Merge of an earlier machine
# ---------------------------------------------------------------------------


def test_an_earlier_mac_machine_merges_into_the_agent_that_appears() -> None:
    agent = AgentClaim(
        agent_id="a-new", name="laptop", macs=("aa:bb:cc:00:00:01",), addresses=("10.50.1.5",)
    )
    prior = [
        PriorMachine(
            key="mac:aa:bb:cc:00:00:01",
            addresses=("10.50.1.5",),
            macs=("aa:bb:cc:00:00:01",),
            merged_from=("ip:10.50.1.4",),
            first_seen=_t(-500),
        )
    ]

    result = cluster_machines(_facts("10.50.1.5"), agents=[agent], prior=prior)

    machine = result.machines[0]
    assert machine.key == "agent:a-new"
    assert machine.merged_from == ("ip:10.50.1.4", "mac:aa:bb:cc:00:00:01")
    assert machine.first_seen == _t(-500).replace(tzinfo=None), "the history is kept"
    assert result.merged == {"mac:aa:bb:cc:00:00:01": "agent:a-new"}


def test_an_earlier_ip_machine_merges_into_the_agent_that_appears() -> None:
    agent = AgentClaim(agent_id="a-new", name="vm", addresses=("10.40.0.50",))
    prior = [PriorMachine(key="ip:10.40.0.50", addresses=("10.40.0.50",))]

    result = cluster_machines(_facts("10.40.0.50"), agents=[agent], prior=prior)

    assert result.merged == {"ip:10.40.0.50": "agent:a-new"}


def test_a_machine_that_keeps_its_key_keeps_its_merges() -> None:
    agent = AgentClaim(agent_id="a-1", name="vm", addresses=("10.40.0.50",))
    prior = [
        PriorMachine(key="agent:a-1", addresses=("10.40.0.50",), merged_from=("ip:10.40.0.50",))
    ]

    result = cluster_machines(_facts("10.40.0.50"), agents=[agent], prior=prior)

    assert result.machines[0].merged_from == ("ip:10.40.0.50",)
    assert result.merged == {}


def test_a_mac_machine_never_merges_sideways() -> None:
    """NEGATIVE CONTROL: an address that moved to another MAC is another device."""
    lease = DhcpLease(ip="10.50.1.228", mac="aa:bb:cc:00:00:02", last_seen=_t(40))
    prior = [PriorMachine(key="mac:aa:bb:cc:00:00:01", addresses=("10.50.1.228",))]

    result = cluster_machines(_facts("10.50.1.228"), leases=[lease], prior=prior)

    assert result.merged == {}
    assert result.machines[0].merged_from == ()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("AA-BB-CC-DD-EE-FF", "aa:bb:cc:dd:ee:ff"),
        ("aabb.ccdd.eeff", "aa:bb:cc:dd:ee:ff"),
        ("00:00:00:00:00:00", None),
        ("ff:ff:ff:ff:ff:ff", None),
        ("nonsense", None),
    ],
)
def test_normalize_mac(raw: str, expected: str | None) -> None:
    assert normalize_mac(raw) == expected


def test_short_name_and_numeric_address_order() -> None:
    assert short_name("Depot.Example.Test.") == "depot"
    ordered = sorted(["10.0.0.10", "10.0.0.9", "2001:db8::1", "192.0.2.1"], key=address_sort_key)
    assert ordered == ["10.0.0.9", "10.0.0.10", "192.0.2.1", "2001:db8::1"]


def test_the_primary_address_is_the_busiest_on_the_network_and_the_agent_counts_once() -> None:
    """Production put a bridge gateway first and summed the agent's documents
    fourteen times. The network's figure picks the primary. The agent's own
    documents sit on the machine once."""
    from datetime import UTC, datetime

    now = datetime(2026, 10, 2, 12, 0, tzinfo=UTC)
    facts = {
        "10.0.8.119": AddressFacts(ip="10.0.8.119", events=10_939, last_seen=now),
        "10.0.99.1": AddressFacts(ip="10.0.99.1", events=0, last_seen=now),
        "172.31.1.1": AddressFacts(ip="172.31.1.1", events=0, last_seen=now),
    }
    agent = AgentClaim(
        agent_id="a-proxy",
        name="proxy",
        addresses=("10.0.99.1", "10.0.8.119", "172.31.1.1"),
        last_report=now,
        docs=1_336_895,
    )
    machines = cluster_machines(list(facts.values()), agents=[agent]).machines
    assert len(machines) == 1
    machine = machines[0]
    assert machine.primary_ip == "10.0.8.119"
    assert machine.events == 10_939 + 1_336_895
