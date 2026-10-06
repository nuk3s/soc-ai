"""A synthetic estate for the estate model tests: three behaviour groups and five outliers.

Not a test module. The estate model tests import it.

* 100 desks: a working day of flows, a desk user, a browser's worth of names.
* 100 servers: a few served ports with heavy traffic, around the clock.
* 100 printers: three served ports, a trickle of flows, no agent.
* 5 planted outliers. Each one breaks a group on two or three features, and
  :data:`PLANTED_FEATURES` names the features the reason must name.

Every value is drawn from one seeded generator, so the estate is the same on
every run. Addresses come from the documentation ranges.
"""

from __future__ import annotations

import random
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

from soc_ai.store.models import EntityProfile

SEED = 20261004
GROUP_SIZE = 100


@dataclass
class Host:
    key: str
    group: str
    # dimension -> (coverage, support days, vector)
    rows: dict[str, tuple[str, int, Any]] = field(default_factory=dict)
    role: str | None = None
    role_confidence: float | None = None


def _members(prefix: str, n: int, per_member: float) -> dict[str, Any]:
    return {f"{prefix}{i}": {"count": int(per_member)} for i in range(max(0, n))}


def _hours(hours: Iterable[int], per_hour: int) -> dict[str, Any]:
    return {str(h): {"count": per_hour} for h in hours}


def _rate(work: float, off: float, weekend: float) -> dict[str, Any]:
    return {
        "work": {"median": work, "dispersion": 1.0, "support_days": 20, "samples": 200},
        "off": {"median": off, "dispersion": 1.0, "support_days": 20, "samples": 200},
        "weekend": {"median": weekend, "dispersion": 1.0, "support_days": 8, "samples": 80},
        "hourly": {"start": "2026-09-01T00:00:00+00:00", "counts": [1] * 24},
    }


def _set_row(prefix: str, n: int, per_day: float, days: int) -> tuple[str, int, Any]:
    n = max(1, n)
    return ("measured", days, _members(prefix, n, per_day * days / n))


def desk(rng: random.Random, key: str, days: int = 30) -> Host:
    host = Host(key=key, group="desk")
    j = rng.uniform
    host.rows["peers_out"] = _set_row("peer", round(j(22, 28)), j(380, 420), days)
    host.rows["consumed_ports"] = _set_row("", round(j(4, 6)), j(380, 420), days)
    host.rows["served_ports"] = _set_row("", 1, j(2, 4), days)
    host.rows["dns_names"] = _set_row("name", round(j(55, 65)), j(900, 1100), days)
    host.rows["process_names"] = _set_row("proc", round(j(85, 95)), j(1900, 2100), days)
    host.rows["process_parents"] = _set_row("parent", round(j(28, 32)), j(1900, 2100), days)
    host.rows["logon_users"] = _set_row("user", 1, j(8, 12), days)
    host.rows["active_hours"] = ("measured", days, _hours(range(8, 18), 1000))
    host.rows["connection_rate"] = ("measured", days, _rate(j(45, 55), j(4, 6), j(1.5, 2.5)))
    return host


def server(rng: random.Random, key: str, days: int = 30) -> Host:
    host = Host(key=key, group="server")
    j = rng.uniform
    host.rows["peers_out"] = _set_row("peer", round(j(7, 9)), j(1900, 2100), days)
    host.rows["consumed_ports"] = _set_row("", 3, j(1900, 2100), days)
    host.rows["served_ports"] = _set_row("", round(j(5, 7)), j(4800, 5200), days)
    host.rows["dns_names"] = _set_row("name", round(j(9, 11)), j(180, 220), days)
    host.rows["process_names"] = _set_row("proc", round(j(145, 155)), j(9500, 10500), days)
    host.rows["process_parents"] = _set_row("parent", round(j(38, 42)), j(9500, 10500), days)
    host.rows["logon_users"] = _set_row("user", round(j(2.6, 3.4)), j(18, 22), days)
    host.rows["active_hours"] = ("measured", days, _hours(range(24), 1000))
    host.rows["connection_rate"] = ("measured", days, _rate(j(190, 210), j(190, 210), j(190, 210)))
    return host


def printer(rng: random.Random, key: str, days: int = 30) -> Host:
    host = Host(key=key, group="printer")
    j = rng.uniform
    host.rows["peers_out"] = _set_row("peer", 2, j(9, 11), days)
    host.rows["consumed_ports"] = _set_row("", 1, j(9, 11), days)
    host.rows["served_ports"] = _set_row("", 3, j(45, 55), days)
    host.rows["dns_names"] = _set_row("name", 2, j(9, 11), days)
    # No agent: the process and logon planes are blind.
    for dim in ("process_names", "process_parents", "logon_users"):
        host.rows[dim] = ("blind", 0, None)
    host.rows["active_hours"] = ("measured", days, _hours(range(6, 18), 50))
    host.rows["connection_rate"] = ("measured", days, _rate(j(2.5, 3.5), j(0.8, 1.2), 0.0))
    return host


# The planted outliers, with the features the reason must name for each.
PLANTED_FEATURES: dict[str, set[str]] = {
    # A desk that serves forty ports, with heavy inbound flows.
    "198.51.100.1": {"served_ports.members", "served_ports.per_day"},
    # A desk with thirty logon users.
    "198.51.100.2": {"logon_users.members", "logon_users.per_day"},
    # A desk active all night.
    "198.51.100.3": {"active_hours.night_share", "active_hours.hours"},
    # A server that reaches six hundred peers.
    "198.51.100.4": {"peers_out.members", "peers_out.per_day"},
    # A printer that runs processes.
    "198.51.100.5": {"process_names.members", "plane.process", "process_parents.members"},
}


def _planted(rng: random.Random) -> list[Host]:
    days = 30
    one = desk(rng, "198.51.100.1")
    one.rows["served_ports"] = _set_row("", 40, 9000, days)
    two = desk(rng, "198.51.100.2")
    two.rows["logon_users"] = _set_row("user", 30, 400, days)
    three = desk(rng, "198.51.100.3")
    three.rows["active_hours"] = (
        "measured",
        days,
        {**_hours(range(24), 400), **_hours(range(6), 4000)},
    )
    four = server(rng, "198.51.100.4")
    four.rows["peers_out"] = _set_row("peer", 600, 60000, days)
    five = printer(rng, "198.51.100.5")
    five.rows["process_names"] = _set_row("proc", 200, 5000, days)
    five.rows["process_parents"] = _set_row("parent", 60, 5000, days)
    for host in (one, two, three, four, five):
        host.group = "planted"
    return [one, two, three, four, five]


def estate(*, seed: int = SEED, planted: bool = True, days: int = 30) -> list[Host]:
    """The 300 hosts of the three groups, and the 5 planted outliers."""
    rng = random.Random(seed)
    hosts: list[Host] = []
    for n in range(GROUP_SIZE):
        hosts.append(desk(rng, f"192.0.2.{n + 1}", days))
    for n in range(GROUP_SIZE):
        hosts.append(server(rng, f"203.0.113.{n + 1}", days))
    for n in range(GROUP_SIZE):
        hosts.append(printer(rng, f"198.18.0.{n + 1}", days))
    if planted:
        hosts.extend(_planted(rng))
    return hosts


def desk_median(key: str, days: int = 30) -> Host:
    """A desk at the middle of every desk range: identical to its group."""
    host = Host(key=key, group="desk")
    host.rows["peers_out"] = _set_row("peer", 25, 400, days)
    host.rows["consumed_ports"] = _set_row("", 5, 400, days)
    host.rows["served_ports"] = _set_row("", 1, 3, days)
    host.rows["dns_names"] = _set_row("name", 60, 1000, days)
    host.rows["process_names"] = _set_row("proc", 90, 2000, days)
    host.rows["process_parents"] = _set_row("parent", 30, 2000, days)
    host.rows["logon_users"] = _set_row("user", 1, 10, days)
    host.rows["active_hours"] = ("measured", days, _hours(range(8, 18), 1000))
    host.rows["connection_rate"] = ("measured", days, _rate(50, 5, 2))
    return host


def appliances(count: int = 6, days: int = 30) -> list[Host]:
    """A small group of identical appliances, far from every other group.

    An isolation forest isolates a small tight group in few cuts, so its
    members can score high. They match their own group exactly, and no
    feature departs from it.
    """
    out: list[Host] = []
    for n in range(count):
        host = Host(key=f"198.18.1.{n + 1}", group="appliance")
        host.rows["peers_out"] = _set_row("peer", 1, 20000, days)
        host.rows["consumed_ports"] = _set_row("", 1, 20000, days)
        host.rows["served_ports"] = _set_row("", 12, 20000, days)
        host.rows["dns_names"] = ("blind", 0, None)
        for dim in ("process_names", "process_parents", "logon_users"):
            host.rows[dim] = ("blind", 0, None)
        host.rows["active_hours"] = ("measured", days, _hours(range(24), 5000))
        host.rows["connection_rate"] = ("measured", days, _rate(800, 800, 800))
        out.append(host)
    return out


def dev_desks(count: int = 6, days: int = 30) -> list[Host]:
    """Desks that each serve a dozen ports: a subgroup, not six outliers.

    Every one of them departs from the desk median on the served ports. Each
    has the other five within a short distance, so the behaviour is a trait
    of a subgroup.
    """
    rng = random.Random(SEED + 1)
    out: list[Host] = []
    for n in range(count):
        host = desk(rng, f"192.0.2.{200 + n}", days)
        host.rows["served_ports"] = _set_row("", 4, rng.uniform(290, 310), days)
        host.group = "dev"
        out.append(host)
    return out


def rows_of(
    hosts: Iterable[Host],
) -> list[tuple[str, str, str, int, str | None, float | None, Any]]:
    """The tuples :func:`vectors_from_rows` reads."""
    out: list[tuple[str, str, str, int, str | None, float | None, Any]] = []
    for host in hosts:
        for dim, (coverage, support, vector) in host.rows.items():
            out.append((host.key, dim, coverage, support, host.role, host.role_confidence, vector))
    return out


def profile_models(
    hosts: Iterable[Host], *, built_at: datetime | None = None
) -> list[EntityProfile]:
    """ORM rows for a bulk insert, stamped relative to now."""
    at = (built_at or datetime.now(UTC) - timedelta(hours=1)).replace(tzinfo=None)
    out: list[EntityProfile] = []
    for host in hosts:
        for dim, (coverage, support, vector) in host.rows.items():
            shape = (
                "numeric"
                if dim == "connection_rate"
                else "active_hours"
                if dim == "active_hours"
                else "categorical"
            )
            out.append(
                EntityProfile(
                    entity_kind="host",
                    entity_key=host.key,
                    dimension=dim,
                    shape=shape,
                    vector_json=vector,
                    coverage=coverage,
                    support_days=support,
                    role=host.role,
                    role_confidence=host.role_confidence,
                    window_days=30,
                    built_at=at,
                )
            )
    return out
