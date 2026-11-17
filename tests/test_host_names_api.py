"""The names read of the lists (J2, prod review 2026-11-12, ui-core 9).

The Alerts and Investigations lists showed "10.x.x.x → 10.y.y.y" while the
Hosts list knew that one end was a workstation with a name and the other a
server. ``GET /hosts/names`` answers the name and the role of each address of a
list page in one read, with the name and the role the Hosts list shows.

The negative controls: an address that no machine holds is left out, and so
is a machine with no name and no role, so the console prints the address alone
and draws no empty brackets.
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from typing import Any

from fastapi.testclient import TestClient
from soc_ai.store import host_dossier as dossier_store
from soc_ai.store import host_machines
from soc_ai.store.host_machines import cluster_machines

from tests.test_hosts_api import (  # noqa: F401 - the shared fixtures
    _LEASE,
    _NEXUS,
    _PROXY,
    client,
    estate,
)


def _names(client: TestClient, *ips: str) -> dict[str, Any]:  # noqa: F811 - the fixture
    response = client.get("/api/v1/hosts/names", params=[("ip", ip) for ip in ips])
    assert response.status_code == 200, response.text
    hosts: dict[str, Any] = response.json()["hosts"]
    return hosts


def test_each_address_carries_the_name_and_the_role_of_its_machine(
    estate: TestClient,  # noqa: F811 - the fixture
) -> None:
    hosts = _names(estate, "10.40.0.119", "10.41.99.1", "10.40.0.129")

    # The primary address and a second address of one machine.
    assert hosts["10.40.0.119"] == {
        "key": "agent:a-proxy",
        "name": "proxy",
        "role": "server",
        "roleGuess": False,
    }
    assert hosts["10.41.99.1"]["name"] == "proxy"
    # A declared role wins over the inferred one, as on the Hosts list.
    assert hosts["10.40.0.129"]["name"] == "nexus"
    assert hosts["10.40.0.129"]["role"] == "workstation"


def test_a_withheld_role_is_marked_as_a_guess(estate: TestClient) -> None:  # noqa: F811
    hosts = _names(estate, "10.50.1.135")

    assert hosts["10.50.1.135"]["name"] == "sensor-view"
    assert hosts["10.50.1.135"]["role"] == "iot"
    assert hosts["10.50.1.135"]["roleGuess"] is True


def test_an_address_with_no_machine_is_left_out(estate: TestClient) -> None:  # noqa: F811
    # NEGATIVE CONTROL. The read names only what the Hosts data holds.
    assert _names(estate, "10.99.0.1") == {}


def test_a_machine_with_no_name_and_no_role_is_left_out(estate: TestClient) -> None:  # noqa: F811
    # NEGATIVE CONTROL. An address with a machine and nothing to say about it
    # prints alone in the console.
    async def unnamed() -> None:
        maker = estate.app.state.db_sessionmaker  # type: ignore[attr-defined]
        async with maker() as db:
            await dossier_store.upsert_host(db, "10.70.0.4", event_count=3)
            await db.commit()
        # The sweep clusters the address into a machine of its own, with no
        # DNS name, no agent, no lease and no role.
        async with maker() as db:
            facts = await host_machines.load_address_facts(
                db,
                dns_names={},
                now=datetime.now(UTC),
                min_confidence=0.6,
                staleness_hours=72,
            )
            prior = await host_machines.load_prior(db)
        clustering = cluster_machines(facts, agents=[_PROXY, _NEXUS], leases=[_LEASE], prior=prior)
        async with maker() as db:
            await host_machines.persist_clustering(db, clustering, facts, now=datetime.now(UTC))

    asyncio.run(unnamed())
    rows = estate.get("/api/v1/hosts", params={"activity": "all", "q": "10.70.0.4"}).json()["rows"]
    assert [(r["key"], r["name"], r["role"]["state"]) for r in rows] == [
        ("ip:10.70.0.4", None, "unknown")
    ]
    hosts = _names(estate, "10.70.0.4", "10.40.0.119")

    assert "10.70.0.4" not in hosts
    assert hosts["10.40.0.119"]["name"] == "proxy"


def test_no_address_is_an_empty_answer(estate: TestClient) -> None:  # noqa: F811
    assert _names(estate) == {}


def test_too_many_addresses_is_a_422(estate: TestClient) -> None:  # noqa: F811
    response = estate.get(
        "/api/v1/hosts/names", params=[("ip", f"10.80.{i // 250}.{i % 250}") for i in range(201)]
    )

    assert response.status_code == 422
    assert "200" in response.text


def test_the_names_route_is_not_read_as_a_machine_key(estate: TestClient) -> None:  # noqa: F811
    # The route sits before /hosts/{key}. Read as a key it would be a 404.
    response = estate.get("/api/v1/hosts/names")

    assert response.status_code == 200
    assert response.json() == {"hosts": {}}
