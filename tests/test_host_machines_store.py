"""Tests for the machine store: the sweep's last step, and the membership reads.

The clustering itself is pure and tested in ``tests/test_host_machines.py``.
These tests run the I/O half against a scratch SQLite database migrated to
head: the rows the sweep writes, the address pointers, the history it keeps,
the merge it records, and the membership the joins read.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from soc_ai.config import Settings
from soc_ai.store import host_dossier as dossier_store
from soc_ai.store import host_machines
from soc_ai.store.db import make_engine, make_sessionmaker, run_migrations
from soc_ai.store.host_machines import (
    AgentClaim,
    ContainerSighting,
    DhcpLease,
    cluster_machines,
)
from soc_ai.store.models import HostDossier, HostMachine
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker

_T0 = datetime(2026, 9, 20, 8, 0, tzinfo=UTC)
_NOW = datetime(2026, 9, 21, 8, 0, tzinfo=UTC)

_DEPOT = AgentClaim(
    agent_id="a-depot",
    name="depot",
    addresses=("10.40.0.75", "172.18.0.1", "172.17.0.1"),
)


def _t(hours: int) -> datetime:
    return _T0 + timedelta(hours=hours)


async def _db(settings: Settings) -> tuple[AsyncEngine, async_sessionmaker[AsyncSession]]:
    engine = make_engine(settings)
    await run_migrations(engine)
    return engine, make_sessionmaker(engine)


async def _seed(maker: async_sessionmaker[AsyncSession], *ips: str, events: int = 5) -> None:
    async with maker() as db:
        for ip in ips:
            await dossier_store.upsert_host(
                db, ip, first_seen=_t(0), last_seen=_t(1), event_count=events
            )
        await db.commit()


async def _name(maker: async_sessionmaker[AsyncSession], ip: str, value: str) -> None:
    async with maker() as db:
        await dossier_store.set_override(db, ip, "hostname", value, actor="analyst")


async def _sweep(
    maker: async_sessionmaker[AsyncSession],
    *,
    agents: list[AgentClaim] | None = None,
    leases: list[DhcpLease] | None = None,
    sightings: list[ContainerSighting] | None = None,
    dns: dict[str, str] | None = None,
    now: datetime = _NOW,
) -> host_machines.PersistStats:
    async with maker() as db:
        facts = await host_machines.load_address_facts(
            db, dns_names=dns, now=now, min_confidence=0.6, staleness_hours=72
        )
        prior = await host_machines.load_prior(db)
    clustering = cluster_machines(
        facts,
        agents=agents or [],
        leases=leases or [],
        sightings=sightings or [],
        prior=prior,
    )
    async with maker() as db:
        return await host_machines.persist_clustering(db, clustering, facts, now=now)


async def _rows(maker: async_sessionmaker[AsyncSession]) -> dict[str, HostMachine]:
    async with maker() as db:
        return {r.machine_key: r for r in (await db.scalars(select(HostMachine))).all()}


async def _pointers(
    maker: async_sessionmaker[AsyncSession],
) -> dict[str, tuple[int | None, str | None]]:
    async with maker() as db:
        rows = (
            await db.execute(
                select(HostDossier.ip, HostDossier.machine_id, HostDossier.address_kind)
            )
        ).all()
    return {str(ip): (machine_id, kind) for ip, machine_id, kind in rows}


# ---------------------------------------------------------------------------
# Persistence
# ---------------------------------------------------------------------------


async def test_persist_writes_one_row_per_machine_and_points_every_address(
    settings_kratos: Settings,
) -> None:
    engine, maker = await _db(settings_kratos)
    await _seed(maker, "10.40.0.75", "172.18.0.1", "172.18.0.7", "10.60.0.9")

    stats = await _sweep(
        maker,
        agents=[_DEPOT],
        sightings=[ContainerSighting(ip="172.18.0.7", agent_id="a-depot")],
    )

    rows = await _rows(maker)
    assert set(rows) == {"agent:a-depot", "ip:10.60.0.9"}
    assert stats.machines == 2
    depot = rows["agent:a-depot"]
    assert (depot.name, depot.name_source, depot.agent_name) == ("depot", "agent", "depot")
    assert (depot.address_count, depot.container_count) == (2, 1)
    assert depot.event_count == 10
    pointers = await _pointers(maker)
    assert pointers["10.40.0.75"] == (depot.id, "agent")
    assert pointers["172.18.0.1"] == (depot.id, "agent")
    assert pointers["172.18.0.7"] == (depot.id, "container")
    assert pointers["10.60.0.9"] == (rows["ip:10.60.0.9"].id, "network")
    await engine.dispose()


async def test_a_second_sweep_over_the_same_census_changes_nothing(
    settings_kratos: Settings,
) -> None:
    engine, maker = await _db(settings_kratos)
    await _seed(maker, "10.40.0.75", "10.60.0.9")
    await _sweep(maker, agents=[_DEPOT])
    first = {k: r.id for k, r in (await _rows(maker)).items()}

    await _sweep(maker, agents=[_DEPOT])

    assert {k: r.id for k, r in (await _rows(maker)).items()} == first
    await engine.dispose()


async def test_an_address_that_leaves_the_census_stays_in_the_machine_history(
    settings_kratos: Settings,
) -> None:
    engine, maker = await _db(settings_kratos)
    await _seed(maker, "10.40.0.75", "172.18.0.1")
    await _sweep(maker, agents=[_DEPOT])
    async with maker() as db:
        await dossier_store.delete_hosts(db, ["172.18.0.1"])

    await _sweep(maker, agents=[_DEPOT])

    depot = (await _rows(maker))["agent:a-depot"]
    assert depot.address_count == 1
    history = {entry["ip"]: entry for entry in depot.addresses_json or []}
    assert history["10.40.0.75"]["current"] is True
    assert history["172.18.0.1"]["current"] is False
    assert history["172.18.0.1"]["kind"] == "agent"
    await engine.dispose()


async def test_a_machine_the_sweep_no_longer_builds_stays_as_history(
    settings_kratos: Settings,
) -> None:
    engine, maker = await _db(settings_kratos)
    await _seed(maker, "10.60.0.9")
    await _sweep(maker)
    async with maker() as db:
        await dossier_store.delete_hosts(db, ["10.60.0.9"])

    stats = await _sweep(maker)

    gone = (await _rows(maker))["ip:10.60.0.9"]
    assert gone.address_count == 0
    assert stats.retired == 1
    # Stale history goes: a machine unseen past the window is pruned.
    stats = await _sweep(maker, now=_NOW + timedelta(days=60))
    assert stats.pruned == 1
    assert "ip:10.60.0.9" not in await _rows(maker)
    await engine.dispose()


async def test_an_agent_that_appears_absorbs_the_earlier_mac_machine(
    settings_kratos: Settings,
) -> None:
    engine, maker = await _db(settings_kratos)
    await _seed(maker, "10.50.1.5")
    lease = DhcpLease(ip="10.50.1.5", mac="aa:bb:cc:00:00:01", hostname="laptop", last_seen=_t(1))
    await _sweep(maker, leases=[lease])
    assert set(await _rows(maker)) == {"mac:aa:bb:cc:00:00:01"}
    agent = AgentClaim(
        agent_id="a-new", name="laptop", macs=("aa:bb:cc:00:00:01",), addresses=("10.50.1.5",)
    )

    stats = await _sweep(maker, agents=[agent], leases=[lease])

    rows = await _rows(maker)
    assert set(rows) == {"agent:a-new"}
    assert rows["agent:a-new"].merged_from_json == ["mac:aa:bb:cc:00:00:01"]
    assert stats.merged == 1
    pointers = await _pointers(maker)
    assert pointers["10.50.1.5"] == (rows["agent:a-new"].id, "agent")
    await engine.dispose()


async def test_a_declared_hostname_names_the_machine(settings_kratos: Settings) -> None:
    engine, maker = await _db(settings_kratos)
    await _seed(maker, "10.40.0.75")
    await _name(maker, "10.40.0.75", "registry-01")

    await _sweep(maker, agents=[_DEPOT])

    depot = (await _rows(maker))["agent:a-depot"]
    assert (depot.name, depot.name_source) == ("registry-01", "declared")
    assert {"value": "depot", "source": "agent"} in (depot.names_json or [])
    await engine.dispose()


# ---------------------------------------------------------------------------
# Membership reads
# ---------------------------------------------------------------------------

_DB_A = AgentClaim(agent_id="a-db-a", name="db", addresses=("10.40.0.21", "10.40.0.22"))


async def _two_machines(maker: async_sessionmaker[AsyncSession]) -> None:
    """One machine with three addresses, one machine with one, one shared label."""
    await _seed(maker, "10.40.0.21", "10.40.0.22", "10.40.3.21", "10.40.0.30")
    await _sweep(
        maker,
        agents=[_DB_A, AgentClaim(agent_id="a-ws", name="ws-7", addresses=("10.40.0.30",))],
        dns={
            "10.40.3.21": "db.example.test",
            "10.40.0.30": "db.other.example.test",
        },
    )


async def test_an_address_resolves_to_its_machine(settings_kratos: Settings) -> None:
    engine, maker = await _db(settings_kratos)
    await _two_machines(maker)

    async with maker() as db:
        held = await host_machines.resolve_membership(db, "10.40.0.22")

    assert held is not None
    assert held.key == "agent:a-db-a"
    assert held.matched == "address"
    # The third address joins through its DNS name: "db" is one machine's name.
    assert set(held.addresses) == {"10.40.0.21", "10.40.0.22", "10.40.3.21"}
    await engine.dispose()


async def test_a_name_an_agent_id_and_a_key_resolve_to_their_machine(
    settings_kratos: Settings,
) -> None:
    engine, maker = await _db(settings_kratos)
    await _two_machines(maker)

    async with maker() as db:
        by_name = await host_machines.resolve_membership(db, "WS-7")
        by_agent = await host_machines.resolve_membership(db, "a-ws")
        by_key = await host_machines.resolve_membership(db, "agent:a-ws")
        by_fqdn = await host_machines.resolve_membership(db, "ws-7.example.test")
        nobody = await host_machines.resolve_membership(db, "no-such-host")

    assert by_name is not None and by_name.key == "agent:a-ws"
    assert by_name.matched == "name"
    assert by_agent is not None and (by_agent.key, by_agent.matched) == ("agent:a-ws", "agent")
    assert by_key is not None and by_key.key == "agent:a-ws"
    assert by_fqdn is not None and by_fqdn.key == "agent:a-ws"
    assert nobody is None
    await engine.dispose()


async def test_the_entity_expansion_is_every_address_and_name_of_the_machine(
    settings_kratos: Settings,
) -> None:
    engine, maker = await _db(settings_kratos)
    await _two_machines(maker)

    async with maker() as db:
        from_address = await host_machines.entity_expansion(db, "10.40.0.21")
        from_name = await host_machines.entity_expansion(db, "ws-7")
        unknown = await host_machines.entity_expansion(db, "printer-9")

    assert from_address[0] == "10.40.0.21"
    assert {"10.40.0.21", "10.40.0.22", "10.40.3.21", "db", "db.example.test"} <= set(from_address)
    # The name lane of the other machine never joins this one.
    assert "10.40.0.30" not in from_address
    assert set(from_name) >= {"ws-7", "10.40.0.30"}
    assert unknown == ["printer-9"]
    await engine.dispose()


async def test_a_label_two_machines_share_joins_neither(settings_kratos: Settings) -> None:
    """NEGATIVE CONTROL: the label "db" is the first label of names on two machines."""
    engine, maker = await _db(settings_kratos)
    await _two_machines(maker)

    async with maker() as db:
        ws = await host_machines.entity_expansion(db, "10.40.0.30")

    assert "db.other.example.test" in ws
    assert "db" not in ws
    await engine.dispose()


async def test_the_old_alias_read_answers_machine_membership(settings_kratos: Settings) -> None:
    """``entity_aliases`` keeps its name for its callers and reads the machine."""
    engine, maker = await _db(settings_kratos)
    await _two_machines(maker)

    async with maker() as db:
        aliases = await dossier_store.entity_aliases(db, "10.40.0.21")
        nobody = await dossier_store.entity_aliases(db, "printer-9")

    assert "10.40.0.21" not in aliases
    assert {"10.40.0.22", "10.40.3.21", "db"} <= set(aliases)
    assert "10.40.0.30" not in aliases
    assert nobody == []
    await engine.dispose()
