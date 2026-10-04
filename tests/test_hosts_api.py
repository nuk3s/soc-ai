"""Tests for the machine API (``soc_ai/api/webui/routes_hosts.py``).

The Hosts screen had one row per address, a search that matched an address in
the middle ("8.1" found 192.168.1.123), an address sort in text order, a role
filter "unknown" that listed 0 hosts under a bar that said 250, and no sort
direction. These tests drive the real app on a scratch database seeded the way
a sweep leaves it, and read the answers through the API.

The estate, relative to now so it never ages into a different window:

* ``proxy``: an agent machine with three addresses, a fresh inferred role.
* ``nexus``: an agent named after a gTLD, with a declared role.
* ``sensor-view``: a DHCP device first seen two days ago, a low-confidence role.
* ``quiet``: one address with no events this window and a stale role.
* an unnamed address with no role row, never built, with an open conflict.
"""

from __future__ import annotations

import asyncio
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from typing import Any
from unittest.mock import AsyncMock, patch
from urllib.parse import quote

import pytest
from fastapi.testclient import TestClient
from soc_ai.config import Settings
from soc_ai.dossier.types import Fact
from soc_ai.main import create_app
from soc_ai.store import host_dossier as dossier_store
from soc_ai.store import host_machines
from soc_ai.store.host_machines import AgentClaim, DhcpLease, cluster_machines
from soc_ai.store.models import HostDossier, HostDossierField
from sqlalchemy import update

_NOW = datetime.now(UTC).replace(tzinfo=None, microsecond=0)

_PROXY = AgentClaim(
    agent_id="a-proxy",
    name="proxy",
    os="Debian GNU/Linux 13",
    macs=("52:54:00:00:00:01",),
    addresses=("10.40.0.119", "10.41.99.1", "10.42.1.5"),
    last_report=_NOW,
)
_NEXUS = AgentClaim(
    agent_id="a-nexus",
    name="nexus",
    os="Fedora Linux 43",
    addresses=("10.40.0.129",),
    last_report=_NOW,
)
_LEASE = DhcpLease(
    ip="10.50.1.135",
    mac="02:00:5e:10:00:27",
    hostname="sensor-view",
    first_seen=_NOW - timedelta(days=2),
    last_seen=_NOW - timedelta(hours=1),
)


def _client(settings: Settings) -> Iterator[TestClient]:
    fake_es = AsyncMock()
    with (
        patch("soc_ai.so_client.elastic.AsyncElasticsearch", return_value=fake_es),
        patch("soc_ai.main.make_auth", return_value=AsyncMock()),
        patch("soc_ai.main.get_settings", return_value=settings),
    ):
        app = create_app()
        with TestClient(app) as client:
            yield client


@pytest.fixture
def client(settings_kratos: Settings) -> Iterator[TestClient]:
    yield from _client(settings_kratos)


def _role(value: str, *, confidence: float = 0.9) -> Fact:
    return Fact(
        field="role",
        value=value,
        confidence=confidence,
        strength="strong" if confidence >= 0.9 else "weak",
        source="behaviour",
        evidence=[f"{value} (from ports)"],
        observed_at=_NOW - timedelta(hours=1),
    )


def _seed(client: TestClient) -> None:
    """Write the estate the way a sweep does: address rows, fields, machines."""

    async def _run() -> None:
        maker = client.app.state.db_sessionmaker  # type: ignore[attr-defined]
        hosts: list[tuple[str, int, timedelta, Fact | None, datetime | None]] = [
            ("10.40.0.119", 9000, timedelta(days=60), _role("server"), _NOW),
            ("10.41.99.1", 3, timedelta(days=60), None, _NOW),
            ("10.42.1.5", 40, timedelta(days=60), None, _NOW),
            ("10.40.0.129", 700, timedelta(days=60), _role("server"), _NOW),
            ("10.50.1.135", 12, timedelta(days=2), _role("iot", confidence=0.5), _NOW),
            ("10.60.0.9", 0, timedelta(days=40), _role("server"), _NOW - timedelta(days=9)),
            ("10.60.0.10", 25, timedelta(days=30), None, None),
        ]
        async with maker() as db:
            for ip, events, age, role, built in hosts:
                host = (
                    await dossier_store.upsert_host(
                        db,
                        ip,
                        first_seen=_NOW - age,
                        last_seen=_NOW - timedelta(hours=1),
                        event_count=events,
                        last_built_at=built,
                        build_error=None,
                        now=built,
                    )
                    if built is not None
                    else await dossier_store.upsert_host(
                        db,
                        ip,
                        first_seen=_NOW - age,
                        last_seen=_NOW - timedelta(hours=1),
                        event_count=events,
                    )
                )
                if role is not None:
                    await dossier_store.upsert_inferred(db, host, role, now=built)
            await db.commit()
        async with maker() as db:
            await dossier_store.set_override(db, "10.40.0.129", "role", "workstation")
        async with maker() as db:
            # An open conflict, due now, on the never-built address.
            await dossier_store.set_override(db, "10.60.0.10", "criticality", "high")
            await db.execute(
                update(HostDossierField)
                .where(HostDossierField.field == "criticality")
                .values(conflict_first_seen_at=_NOW - timedelta(days=1), conflict_observations=5)
            )
            await db.commit()
        async with maker() as db:
            facts = await host_machines.load_address_facts(
                db,
                dns_names={
                    "10.60.0.9": "quiet.example.test",
                    "10.60.0.10": "old-proxy.example.test",
                },
                now=datetime.now(UTC),
                min_confidence=0.6,
                staleness_hours=72,
            )
            prior = await host_machines.load_prior(db)
        clustering = cluster_machines(facts, agents=[_PROXY, _NEXUS], leases=[_LEASE], prior=prior)
        async with maker() as db:
            await host_machines.persist_clustering(db, clustering, facts, now=datetime.now(UTC))

    asyncio.run(_run())


@pytest.fixture
def estate(client: TestClient) -> TestClient:
    _seed(client)
    return client


def _list(client: TestClient, **params: Any) -> dict[str, Any]:
    response = client.get("/api/v1/hosts", params=params)
    assert response.status_code == 200, response.text
    body: dict[str, Any] = response.json()
    return body


def _keys(body: dict[str, Any]) -> list[str]:
    return [row["key"] for row in body["rows"]]


# ---------------------------------------------------------------------------
# One row per machine
# ---------------------------------------------------------------------------


def test_the_list_has_one_row_per_machine(estate: TestClient) -> None:
    body = _list(estate, activity="all")

    assert body["total"] == 5
    proxy = next(row for row in body["rows"] if row["key"] == "agent:a-proxy")
    assert proxy["name"] == "proxy"
    assert proxy["name_source"] == "agent"
    assert proxy["primary_ip"] == "10.40.0.119"
    assert proxy["address_count"] == 3
    assert proxy["addresses"][0] == "10.40.0.119"
    assert proxy["href"] == "/hosts/agent%3Aa-proxy"
    assert proxy["agent"]["name"] == "proxy"
    assert proxy["agent"]["os"] == "Debian GNU/Linux 13"
    assert proxy["events"] == 9043
    assert proxy["role"] == {
        "value": "server",
        "label": "server",
        "confidence": 0.9,
        "state": "inferred",
        "guess": None,
        "stale_hours": None,
    }
    assert set(proxy["flags"]) == {"declared", "conflict", "broken", "new", "rebound"}


def test_the_default_view_hides_a_machine_with_no_events(estate: TestClient) -> None:
    body = _list(estate)

    assert body["total"] == 4
    assert "ip:10.60.0.9" not in _keys(body)


def test_the_role_states_are_the_resolvers(estate: TestClient) -> None:
    rows = {row["key"]: row["role"] for row in _list(estate, activity="all")["rows"]}

    assert rows["agent:a-nexus"]["state"] == "declared"
    assert rows["agent:a-nexus"]["value"] == "workstation"
    assert rows["mac:02:00:5e:10:00:27"]["state"] == "low_confidence"
    assert rows["mac:02:00:5e:10:00:27"]["guess"] == "iot"
    assert rows["ip:10.60.0.9"]["state"] == "stale"
    assert rows["ip:10.60.0.9"]["guess"] == "server"
    assert rows["ip:10.60.0.9"]["stale_hours"] >= 72
    assert rows["ip:10.60.0.10"]["state"] == "unknown"


# ---------------------------------------------------------------------------
# Search
# ---------------------------------------------------------------------------


def test_search_finds_an_agent_named_after_a_gtld(estate: TestClient) -> None:
    assert _keys(_list(estate, q="nexus")) == ["agent:a-nexus"]
    assert _keys(_list(estate, q="NEXUS")) == ["agent:a-nexus"]


def test_search_ignores_the_activity_filter(estate: TestClient) -> None:
    """The quiet machine has no events. An analyst who names it must find it."""
    assert _keys(_list(estate, q="quiet")) == ["ip:10.60.0.9"]


def test_search_matches_an_address_exactly_or_by_prefix(estate: TestClient) -> None:
    assert _keys(_list(estate, q="10.42.1.5")) == ["agent:a-proxy"]
    assert set(_keys(_list(estate, q="10.4"))) == {"agent:a-proxy", "agent:a-nexus"}


def test_search_never_matches_an_address_in_the_middle(estate: TestClient) -> None:
    """NEGATIVE CONTROL: "0.1" sits inside 10.40.0.119, 10.40.0.129 and 10.50.1.135."""
    assert _list(estate, q="0.1")["total"] == 0
    assert _list(estate, q="1.13")["total"] == 0


def test_search_reads_the_mac_the_os_the_role_and_the_agent(estate: TestClient) -> None:
    assert _keys(_list(estate, q="02-00-5E-10")) == ["mac:02:00:5e:10:00:27"]
    assert _keys(_list(estate, q="02:00:5e:10:00:27")) == ["mac:02:00:5e:10:00:27"]
    assert _keys(_list(estate, q="fedora")) == ["agent:a-nexus"]
    assert set(_keys(_list(estate, q="workstation"))) == {"agent:a-nexus"}
    assert _keys(_list(estate, q="sensor-view")) == ["mac:02:00:5e:10:00:27"]
    # A full name finds the machine whose agent reports the bare name.
    assert _keys(_list(estate, q="proxy.lab.example")) == ["agent:a-proxy"]


def test_an_exact_match_ranks_first(estate: TestClient) -> None:
    # "proxy" is the agent's own name, and a substring of the other's DNS name.
    assert _keys(_list(estate, q="proxy")) == ["agent:a-proxy", "ip:10.60.0.10"]


def _seen_at(client: TestClient, ip: str, when: datetime) -> None:
    async def _run() -> None:
        maker = client.app.state.db_sessionmaker  # type: ignore[attr-defined]
        async with maker() as db:
            await db.execute(update(HostDossier).where(HostDossier.ip == ip).values(last_seen=when))
            await db.commit()

    asyncio.run(_run())


def test_the_match_tier_leads_under_an_explicit_sort(estate: TestClient) -> None:
    """The console always sends sort=last_seen&dir=desc.

    The machine whose other name only contains "proxy" was seen later. A bare
    last_seen sort put it above the machine named exactly "proxy".
    """
    _seen_at(estate, "10.60.0.10", _NOW)

    body = _list(estate, q="proxy", sort="last_seen", dir="desc")

    assert _keys(body) == ["agent:a-proxy", "ip:10.60.0.10"]
    assert (body["sort"], body["dir"]) == ("last_seen", "desc")


def test_the_requested_sort_orders_the_rows_inside_one_tier(estate: TestClient) -> None:
    """Both machines match "10.40" by prefix, so the address sort decides."""
    asc = _keys(_list(estate, q="10.40", sort="address", dir="asc"))
    desc = _keys(_list(estate, q="10.40", sort="address", dir="desc"))

    assert asc == ["agent:a-proxy", "agent:a-nexus"]
    assert desc == ["agent:a-nexus", "agent:a-proxy"]


def test_a_role_match_ranks_below_a_name_prefix(estate: TestClient) -> None:
    """NEGATIVE CONTROL: the role "server" equals the query on two machines.

    A role describes a machine and never names it. The machine the operator
    named "server-room-cam" starts with the query, so it leads. It was seen
    last, so the last_seen sort alone puts it at the bottom.
    """

    async def _declare() -> None:
        maker = estate.app.state.db_sessionmaker  # type: ignore[attr-defined]
        async with maker() as db:
            await dossier_store.set_override(db, "10.50.1.135", "hostname", "server-room-cam")

    asyncio.run(_declare())
    _seen_at(estate, "10.50.1.135", _NOW - timedelta(days=3))

    keys = _keys(_list(estate, q="server", sort="last_seen", dir="desc"))
    unsorted = _keys(_list(estate, q="server"))

    assert keys[0] == "mac:02:00:5e:10:00:27"
    assert unsorted[0] == "mac:02:00:5e:10:00:27"
    assert set(keys) == {"mac:02:00:5e:10:00:27", "agent:a-proxy", "ip:10.60.0.9"}


# ---------------------------------------------------------------------------
# Sort
# ---------------------------------------------------------------------------


def test_the_address_sort_is_numeric_in_both_directions(estate: TestClient) -> None:
    asc = [row["primary_ip"] for row in _list(estate, activity="all", sort="address")["rows"]]
    desc = [
        row["primary_ip"]
        for row in _list(estate, activity="all", sort="address", dir="desc")["rows"]
    ]

    assert asc == ["10.40.0.119", "10.40.0.129", "10.50.1.135", "10.60.0.9", "10.60.0.10"]
    assert desc == list(reversed(asc))


@pytest.mark.parametrize("direction", ["asc", "desc"])
def test_nulls_sort_last_in_both_directions(estate: TestClient, direction: str) -> None:
    by_agent = _list(estate, activity="all", sort="agent", dir=direction)["rows"]
    assert [row["agent"] is None for row in by_agent] == [False, False, True, True, True]
    # The one machine with no role and no guess sorts last whichever way.
    by_role = _list(estate, activity="all", sort="role", dir=direction)["rows"]
    assert by_role[-1]["key"] == "ip:10.60.0.10"


@pytest.mark.parametrize(
    "sort", ["name", "address", "role", "agent", "events", "first_seen", "last_seen"]
)
def test_every_column_sorts_in_both_directions(estate: TestClient, sort: str) -> None:
    asc = _list(estate, activity="all", sort=sort, dir="asc")
    desc = _list(estate, activity="all", sort=sort, dir="desc")

    assert (asc["sort"], asc["dir"], desc["dir"]) == (sort, "asc", "desc")
    assert asc["total"] == desc["total"] == 5


def test_the_default_sort_is_last_seen_newest_first(estate: TestClient) -> None:
    body = _list(estate)
    assert (body["sort"], body["dir"]) == ("last_seen", "desc")


def test_events_sort_orders_by_the_machine_sum(estate: TestClient) -> None:
    keys = _keys(_list(estate, activity="all", sort="events", dir="desc"))
    assert keys[0] == "agent:a-proxy"
    assert keys[-1] == "ip:10.60.0.9"


def test_paging_cuts_the_sorted_set(estate: TestClient) -> None:
    whole = _keys(_list(estate, activity="all", sort="address"))
    first = _list(estate, activity="all", sort="address", limit=2)
    second = _list(estate, activity="all", sort="address", limit=2, offset=2)
    assert _keys(first) + _keys(second) == whole[:4]
    assert first["total"] == 5


# ---------------------------------------------------------------------------
# Filters
# ---------------------------------------------------------------------------


def test_the_unknown_role_filter_lists_the_unknown_machines(estate: TestClient) -> None:
    """The bar said 250 unknown and the filter listed 0. They are one set now."""
    body = _list(estate, activity="all", role="unknown")

    assert _keys(body) == ["ip:10.60.0.10"]


def test_the_agent_seen_and_declared_filters(estate: TestClient) -> None:
    assert set(_keys(_list(estate, activity="all", agent="yes"))) == {
        "agent:a-proxy",
        "agent:a-nexus",
    }
    assert _list(estate, activity="all", agent="no")["total"] == 3
    assert _keys(_list(estate, activity="all", seen="new")) == ["mac:02:00:5e:10:00:27"]
    assert set(_keys(_list(estate, activity="all", declared="yes"))) == {
        "agent:a-nexus",
        "ip:10.60.0.10",
    }


@pytest.mark.parametrize(
    ("param", "value"),
    [
        ("sort", "colour"),
        ("dir", "up"),
        ("role", "wizard"),
        ("agent", "maybe"),
        ("activity", "some"),
        ("seen", "old"),
        ("declared", "perhaps"),
    ],
)
def test_an_unknown_value_is_a_422_that_names_the_legal_ones(
    estate: TestClient, param: str, value: str
) -> None:
    response = estate.get("/api/v1/hosts", params={param: value})

    assert response.status_code == 422
    detail = response.json()["detail"]
    assert detail["reason"] == f"unknown_{param}"
    assert value in detail["hint"]


# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------


def test_every_summary_count_equals_its_list_total(estate: TestClient) -> None:
    summary = estate.get("/api/v1/hosts/summary").json()

    def total(**params: Any) -> int:
        return int(_list(estate, activity="all", **params)["total"])

    assert summary["machines"] == total() == 5
    assert summary["with_agent"] == total(agent="yes")
    assert summary["without_agent"] == total(agent="no")
    assert summary["new_7d"] == total(seen="new")
    assert summary["named"] == total(named="yes")
    assert summary["unnamed"] == total(named="no")
    assert summary["needs_attention"] == total(health="attention")
    assert summary["never_built"] == total(health="broken")
    assert summary["conflicts"] == total(conflict="yes")
    for slug, count in summary["roles"].items():
        assert count == total(role=slug), slug
    assert summary["roles"]["unknown"] == 1
    assert summary["roles"]["low_confidence"] == 1
    assert summary["roles"]["stale"] == 1
    assert sum(summary["roles"].values()) == summary["machines"]
    assert summary["addresses"] == 7
    assert summary["conflicts"] == 1
    assert summary["never_built"] == 1


def test_the_summary_counts_under_the_list_activity(estate: TestClient) -> None:
    """The header menus said "unknown 117" over a list of 81.

    The menus count under the activity the list shows. The quiet machine has
    no events, so the active summary leaves it out, and each count equals the
    total of the active list with the same filter.
    """
    summary = estate.get("/api/v1/hosts/summary", params={"activity": "active"}).json()

    def total(**params: Any) -> int:
        return int(_list(estate, activity="active", **params)["total"])

    assert summary["machines"] == total() == 4
    assert summary["with_agent"] == total(agent="yes")
    assert summary["without_agent"] == total(agent="no")
    assert summary["new_7d"] == total(seen="new")
    assert summary["named"] == total(named="yes")
    assert summary["never_built"] == total(health="broken")
    for slug, count in summary["roles"].items():
        assert count == total(role=slug), slug
    # The stale bucket stays in the answer at 0, so the menu can offer it.
    assert summary["roles"]["stale"] == 0
    assert summary["addresses"] == 6


def test_the_summary_defaults_to_every_machine(estate: TestClient) -> None:
    """NEGATIVE CONTROL: the cards send no activity and count every machine."""
    default = estate.get("/api/v1/hosts/summary").json()
    every = estate.get("/api/v1/hosts/summary", params={"activity": "all"}).json()

    assert default["machines"] == every["machines"] == 5
    assert default["roles"]["stale"] == 1
    response = estate.get("/api/v1/hosts/summary", params={"activity": "some"})
    assert response.status_code == 422
    assert response.json()["detail"]["reason"] == "unknown_activity"


def test_the_rebound_flag_needs_a_declaration(estate: TestClient) -> None:
    """Production: 41 machines read "rebound", most with no declaration at all.

    The flag warns that an override may no longer apply. The proxy holds no
    declaration, so its stamp says nothing. The nexus declares its role.
    """

    async def _stamp() -> None:
        maker = estate.app.state.db_sessionmaker  # type: ignore[attr-defined]
        async with maker() as db:
            await db.execute(
                update(HostDossier)
                .where(HostDossier.ip.in_(["10.40.0.119", "10.40.0.129"]))
                .values(identity_rebound_at=_NOW - timedelta(hours=2))
            )
            await db.commit()

    asyncio.run(_stamp())
    rows = {row["key"]: row["flags"] for row in _list(estate, activity="all")["rows"]}

    assert rows["agent:a-proxy"]["rebound"] is False
    assert rows["agent:a-nexus"]["rebound"] is True
    detail = estate.get(f"/api/v1/hosts/{quote('agent:a-proxy', safe='')}").json()
    assert detail["flags"]["rebound"] is False
    assert detail["dossier"]["identity_rebound_at"] is None


# ---------------------------------------------------------------------------
# Resolve and detail
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("value", "key", "matched"),
    [
        ("10.42.1.5", "agent:a-proxy", "address"),
        ("nexus", "agent:a-nexus", "name"),
        ("02-00-5E-10-00-27", "mac:02:00:5e:10:00:27", "mac"),
        ("a-proxy", "agent:a-proxy", "agent"),
    ],
)
def test_resolve_names_the_machine(estate: TestClient, value: str, key: str, matched: str) -> None:
    body = estate.get("/api/v1/hosts/resolve", params={"value": value}).json()

    assert (body["key"], body["matched"]) == (key, matched)


def test_resolve_answers_404_for_nothing(estate: TestClient) -> None:
    response = estate.get("/api/v1/hosts/resolve", params={"value": "printer-9"})

    assert response.status_code == 404
    assert response.json()["detail"]["reason"] == "no_host"


def test_the_machine_page_lists_every_address_and_the_primary_dossier(
    estate: TestClient,
) -> None:
    body = estate.get(f"/api/v1/hosts/{quote('agent:a-proxy', safe='')}").json()

    assert body["key"] == "agent:a-proxy"
    assert [(a["ip"], a["kind"], a["primary"]) for a in body["addresses"]] == [
        ("10.40.0.119", "agent", True),
        ("10.41.99.1", "agent", False),
        ("10.42.1.5", "agent", False),
    ]
    assert body["containers"] == []
    assert body["macs"] == ["52:54:00:00:00:01"]
    assert body["merged_from"] == []
    assert body["dossier"]["ip"] == "10.40.0.119"
    assert body["dossier"]["found"] is True


def test_an_unknown_machine_is_a_404(estate: TestClient) -> None:
    response = estate.get("/api/v1/hosts/agent%3Anobody")

    assert response.status_code == 404
    assert response.json()["detail"]["reason"] == "no_host"


def test_the_per_address_dossier_routes_still_answer(estate: TestClient) -> None:
    listed = estate.get("/api/v1/dossiers", params={"limit": 200}).json()
    assert listed["total"] == 7
    one = estate.get("/api/v1/dossiers/10.41.99.1").json()
    assert one["ip"] == "10.41.99.1"
    assert estate.get("/api/v1/dossiers/summary").status_code == 200
