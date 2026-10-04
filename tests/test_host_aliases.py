"""One machine under two keys: the address and the host name.

The flow lanes key a host on its address. The host-log lanes (process, process
pair, logon user) and the observations they write key it on ``host.name``. The
host page read the address alone and showed "0 observations" and a blind
process baseline for a domain controller whose name held six observations and
175 process names. These tests pin the join, and the negative controls pin the
joins it must refuse: a name two hosts share, a weak name, and a user account.

The join reads machine membership (``soc_ai.store.host_machines``) since
2026-10-02. The seed helpers rebuild the machines after each write, the way the
sweep's last step does.
"""

from __future__ import annotations

import asyncio
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from typing import Any
from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient
from soc_ai.config import Settings
from soc_ai.dossier.types import Fact
from soc_ai.main import create_app
from soc_ai.store import entity_profiles, host_machines
from soc_ai.store import host_dossier as dossier_store
from soc_ai.store.models import EntityObservation

DC = "192.0.2.10"
OTHER = "192.0.2.20"
THIRD = "192.0.2.30"


@pytest.fixture
def client(settings_kratos: Settings) -> Iterator[TestClient]:
    fake_es = AsyncMock()
    with (
        patch("soc_ai.so_client.elastic.AsyncElasticsearch", return_value=fake_es),
        patch("soc_ai.main.make_auth", return_value=AsyncMock()),
        patch("soc_ai.main.get_settings", return_value=settings_kratos),
    ):
        app = create_app()
        with TestClient(app) as test_client:
            yield test_client


def _now() -> datetime:
    return datetime.now(UTC).replace(tzinfo=None)


def _run(client: TestClient, work: Any) -> Any:
    async def go() -> Any:
        async with client.app.state.db_sessionmaker() as db:  # type: ignore[attr-defined]
            out = await work(db)
            await db.commit()
            return out

    return asyncio.run(go())


def _host(client: TestClient, ip: str, hostname: str | None, *, confidence: float = 0.9) -> None:
    async def work(db: Any) -> None:
        host = await dossier_store.upsert_host(db, ip, event_count=10, last_built_at=_now())
        if hostname is not None:
            fact = Fact(
                field="hostname",
                value=hostname,
                confidence=confidence,
                strength="strong" if confidence >= 0.9 else "weak",
                source="hostlog" if confidence >= 0.9 else "banner",
                evidence=[hostname],
                observed_at=_now(),
            )
            await dossier_store.upsert_inferred(db, host, fact, min_confidence=0.0)

    _run(client, work)
    _build_machines(client)


def _build_machines(
    client: TestClient,
    *,
    agents: list[host_machines.AgentClaim] | None = None,
    dns: dict[str, str] | None = None,
) -> None:
    """The sweep's last step over the table as the test left it."""

    async def go() -> None:
        maker = client.app.state.db_sessionmaker  # type: ignore[attr-defined]
        async with maker() as db:
            facts = await host_machines.load_address_facts(
                db, dns_names=dns, now=datetime.now(UTC), min_confidence=0.6, staleness_hours=72
            )
            prior = await host_machines.load_prior(db)
        clustering = host_machines.cluster_machines(facts, agents=agents or [], prior=prior)
        async with maker() as db:
            await host_machines.persist_clustering(db, clustering, facts, now=datetime.now(UTC))

    asyncio.run(go())


def _observation(client: TestClient, key: str, *, kind: str = "host", fp: str = "fp") -> None:
    async def work(db: Any) -> None:
        born = _now() - timedelta(minutes=18)
        db.add(
            EntityObservation(
                entity_kind=kind,
                entity_key=key,
                kind="profile_departure",
                spec_id="prior-new-process",
                fingerprint=fp,
                birth_weight=0.5,
                born_at=born,
                first_seen_at=born,
                occurrences=1,
                source="profile",
                summary=f"seen under {key}",
            )
        )

    _run(client, work)


def _profile(client: TestClient, key: str, dimension: str, coverage: str, vector: Any) -> None:
    async def work(db: Any) -> None:
        await entity_profiles.upsert_profile(
            db,
            entity_kind="host",
            entity_key=key,
            dimension=dimension,
            shape="categorical",
            vector=vector,
            coverage=coverage,
            support_days=0 if coverage == "blind" else 14,
            window_days=30,
        )

    _run(client, work)


def _observations(client: TestClient, entity: str) -> dict[str, Any]:
    res = client.get(f"/api/v1/hunts/observations?entity={entity}")
    assert res.status_code == 200, res.text
    body: dict[str, Any] = res.json()
    return body


# ---------------------------------------------------------------------------
# Observations
# ---------------------------------------------------------------------------


def test_the_host_page_reads_observations_stored_under_the_host_name(
    client: TestClient,
) -> None:
    _host(client, DC, "dc01.example.test")
    _observation(client, "dc01", fp="a")
    _observation(client, "DC01.example.test", fp="b")

    body = _observations(client, DC)
    assert len(body["observations"]) == 2
    assert set(body["aliases"]) == {"dc01.example.test", "dc01"}


def test_a_name_reads_the_observations_stored_under_the_address(client: TestClient) -> None:
    _host(client, DC, "dc01.example.test")
    _observation(client, DC, fp="a")

    body = _observations(client, "dc01")
    assert len(body["observations"]) == 1
    assert DC in body["aliases"]


def test_a_label_two_hosts_share_joins_neither(client: TestClient) -> None:
    """Negative control: ``ws01`` names two machines in two domains.

    The join on the full name still holds. The short label joins nothing,
    because joining it would show one machine's history on the other's page.
    """
    _host(client, DC, "ws01.a.example.test")
    _host(client, OTHER, "ws01.b.example.test")
    _observation(client, "ws01", fp="short")
    _observation(client, "ws01.b.example.test", fp="other-full")

    body = _observations(client, DC)
    assert body["observations"] == []
    assert "ws01" not in body["aliases"]
    assert _observations(client, "ws01")["aliases"] == []
    other = _observations(client, OTHER)
    assert [o["summary"] for o in other["observations"]] == ["seen under ws01.b.example.test"]


def test_a_weak_hostname_joins_nothing(client: TestClient) -> None:
    """Negative control: a share announcement is a hint, not an identity."""
    _host(client, DC, "printer01.example.test", confidence=0.5)
    _observation(client, "printer01", fp="a")

    body = _observations(client, DC)
    assert body["observations"] == []
    assert body["aliases"] == []


def test_an_alias_never_joins_a_user_account(client: TestClient) -> None:
    """Negative control: a user named like a host is a different entity."""
    _host(client, DC, "backup.example.test")
    _observation(client, "backup", kind="user", fp="user-row")

    assert _observations(client, DC)["observations"] == []


# ---------------------------------------------------------------------------
# Dossier: aliases and the profile under the name
# ---------------------------------------------------------------------------


def _dimension(body: dict[str, Any], name: str) -> dict[str, Any]:
    return next(d for d in body["profile"] if d["dimension"] == name)


def test_the_dossier_reads_the_process_baseline_under_the_host_name(
    client: TestClient,
) -> None:
    _host(client, DC, "dc01.example.test")
    _profile(client, DC, "served_ports", "measured", {"88": {"count": 9}})
    _profile(client, DC, "process_names", "blind", None)
    _profile(client, "dc01", "process_names", "measured", {"lsass.exe": {"count": 40}})

    body = client.get(f"/api/v1/dossiers/{DC}").json()
    assert "dc01" in body["aliases"]
    processes = _dimension(body, "process_names")
    assert processes["coverage"] == "measured"
    assert "lsass.exe" in processes["summary"]


def test_a_blind_row_always_states_its_reason(client: TestClient) -> None:
    """A blind row with a null reason read as a quiet host. Each one says why."""
    _host(client, THIRD, None)
    _profile(client, THIRD, "process_names", "blind", None)
    _profile(client, THIRD, "dns_names", "blind", None)

    body = client.get(f"/api/v1/dossiers/{THIRD}").json()
    assert _dimension(body, "process_names")["coverage_reason"] == "no host log in the window"
    assert _dimension(body, "dns_names")["coverage_reason"]


@pytest.fixture
def client_es(settings_kratos: Settings) -> Iterator[tuple[TestClient, AsyncMock]]:
    """The client, and the fake Elasticsearch behind it for a coverage read."""
    fake_es = AsyncMock()
    with (
        patch("soc_ai.so_client.elastic.AsyncElasticsearch", return_value=fake_es),
        patch("soc_ai.main.make_auth", return_value=AsyncMock()),
        patch("soc_ai.main.get_settings", return_value=settings_kratos),
    ):
        app = create_app()
        with TestClient(app) as test_client:
            yield test_client, fake_es


def _coverage_answer(datasets: dict[str, int]) -> dict[str, Any]:
    newest = {"value_as_string": datetime.now(UTC).isoformat()}
    return {
        "hits": {"total": {"value": sum(datasets.values()), "relation": "eq"}},
        "aggregations": {
            "host_datasets": {
                "buckets": [
                    {"key": name, "doc_count": count, "newest": newest}
                    for name, count in datasets.items()
                ]
            },
            "host_agents": {"buckets": []},
            "host_agent_names": {"buckets": []},
        },
    }


_HOST_LOGS_AND_OSQUERY = {
    "system.syslog": 8884,
    "system.auth": 1074,
    "elastic_agent.osquerybeat": 104,
    "osquery_manager.result": 90,
    "elastic_agent": 47,
}


def test_a_blind_process_row_names_the_plane_and_what_the_host_ships(
    client_es: tuple[TestClient, AsyncMock],
) -> None:
    """Dogfood 2026-10-02: "cannot be measured: the agent on this host reports
    no process events". The agent reports host logs and osquery. The reason
    names the missing plane and the planes the host ships."""
    client, fake_es = client_es
    _host(client, DC, "depot.example.test")
    _profile(client, DC, "process_names", "blind", None)
    fake_es.search.return_value = _coverage_answer(_HOST_LOGS_AND_OSQUERY)

    body = client.get(f"/api/v1/dossiers/{DC}").json()

    assert _dimension(body, "process_names")["coverage_reason"] == (
        "this host ships no endpoint process events. It ships host logs and osquery."
    )


def test_a_failed_coverage_read_names_only_what_the_dossier_knows(
    client_es: tuple[TestClient, AsyncMock],
) -> None:
    """NEGATIVE CONTROL: a failed read says nothing about osquery.

    The agent self-report reached the host-log datasets, so the dossier knows
    the host ships host logs. It does not know more, so it claims no more.
    """
    client, fake_es = client_es
    _host(client, DC, "depot.example.test")
    _profile(client, DC, "process_names", "blind", None)
    fake_es.search.side_effect = RuntimeError("grid down")

    body = client.get(f"/api/v1/dossiers/{DC}").json()

    assert _dimension(body, "process_names")["coverage_reason"] == (
        "this host ships no endpoint process events. It ships host logs."
    )


def test_a_process_plane_present_now_is_not_called_absent(
    client_es: tuple[TestClient, AsyncMock],
) -> None:
    """NEGATIVE CONTROL: the host started to ship process events after the sweep."""
    client, fake_es = client_es
    _host(client, DC, "depot.example.test")
    _profile(client, DC, "process_names", "blind", None)
    fake_es.search.return_value = _coverage_answer(
        {**_HOST_LOGS_AND_OSQUERY, "endpoint.events.process": 400}
    )

    reason = _dimension(client.get(f"/api/v1/dossiers/{DC}").json(), "process_names")[
        "coverage_reason"
    ]

    assert "ships no endpoint process events" not in reason
    assert reason == (
        "the last profile sweep found no endpoint process events for this host. "
        "The host ships them now. The next profile sweep reads them."
    )


def test_a_host_with_no_agent_skips_the_coverage_read(
    client_es: tuple[TestClient, AsyncMock],
) -> None:
    """The read runs only where a blind row on a reporting host needs it."""
    client, fake_es = client_es
    _host(client, THIRD, None)
    _profile(client, THIRD, "process_names", "blind", None)

    body = client.get(f"/api/v1/dossiers/{THIRD}").json()

    assert _dimension(body, "process_names")["coverage_reason"] == "no host log in the window"
    fake_es.search.assert_not_awaited()


def test_a_shared_label_does_not_lend_its_profile(client: TestClient) -> None:
    """Negative control: the process baseline of ``ws01`` belongs to nobody."""
    _host(client, DC, "ws01.a.example.test")
    _host(client, OTHER, "ws01.b.example.test")
    _profile(client, DC, "process_names", "blind", None)
    _profile(client, "ws01", "process_names", "measured", {"cmd.exe": {"count": 3}})

    body = client.get(f"/api/v1/dossiers/{DC}").json()
    assert _dimension(body, "process_names")["coverage"] == "blind"


# ---------------------------------------------------------------------------
# Entity: a known name names its host
# ---------------------------------------------------------------------------


def test_the_entity_route_names_the_host_a_known_name_belongs_to(client: TestClient) -> None:
    _host(client, DC, "dc01.example.test")
    assert client.get("/api/v1/entity/dc01").json()["host_ip"] == DC
    assert client.get("/api/v1/entity/DC01.example.test").json()["host_ip"] == DC


def test_the_entity_route_names_no_host_for_a_shared_label(client: TestClient) -> None:
    """Negative control: two hosts answer to ``ws01``, so neither page is the one."""
    _host(client, DC, "ws01.a.example.test")
    _host(client, OTHER, "ws01.b.example.test")
    assert client.get("/api/v1/entity/ws01").json()["host_ip"] is None
    assert client.get("/api/v1/entity/ws01").json()["host_key"] is None
    assert client.get(f"/api/v1/entity/{DC}").json()["host_ip"] is None


# ---------------------------------------------------------------------------
# Machines: one machine with three addresses, and a neighbour sharing a label
# ---------------------------------------------------------------------------

DB_1 = "192.0.2.41"
DB_2 = "192.0.2.42"
DB_3 = "192.0.2.43"
WEB = "192.0.2.50"


def _two_machines(client: TestClient) -> None:
    """``db`` is one agent with three addresses. ``web`` is another agent whose
    address DNS calls ``db.other.example.test``: the label ``db`` is shared."""
    for ip in (DB_1, DB_2, DB_3, WEB):
        _host(client, ip, None)
    _build_machines(
        client,
        agents=[
            host_machines.AgentClaim(agent_id="a-db", name="db", addresses=(DB_1, DB_2, DB_3)),
            host_machines.AgentClaim(agent_id="a-web", name="web", addresses=(WEB,)),
        ],
        dns={WEB: "db.other.example.test"},
    )
    for key, fp in (
        (DB_1, "1"),
        (DB_2, "2"),
        (DB_3, "3"),
        ("db", "name"),
        (WEB, "web"),
        ("db.other.example.test", "web-dns"),
    ):
        _observation(client, key, fp=fp)


def test_one_machine_shows_the_observations_of_every_address_once(client: TestClient) -> None:
    _two_machines(client)

    for entity in (DB_1, DB_3, "db", "DB"):
        body = _observations(client, entity)
        summaries = sorted(o["summary"] for o in body["observations"])
        assert summaries == sorted(f"seen under {key}" for key in (DB_1, DB_2, DB_3, "db")), entity
        assert len({o["id"] for o in body["observations"]}) == 4


def test_a_machine_that_shares_a_label_never_shows_the_other_machines_observations(
    client: TestClient,
) -> None:
    """Negative control: ``db`` is a label of ``web``'s DNS name and the name of
    the other machine. The join reads machines, so ``web`` gets none of it."""
    _two_machines(client)

    body = _observations(client, WEB)

    assert sorted(o["summary"] for o in body["observations"]) == [
        f"seen under {WEB}",
        "seen under db.other.example.test",
    ]
    assert "db" not in body["aliases"]
    assert DB_1 not in body["aliases"]


def test_the_entity_route_names_the_machine_of_an_address_or_a_name(client: TestClient) -> None:
    _two_machines(client)

    by_address = client.get(f"/api/v1/entity/{DB_2}").json()
    assert by_address["host_key"] == "agent:a-db"
    assert by_address["host_ip"] is None
    by_name = client.get("/api/v1/entity/db").json()
    assert by_name["host_key"] == "agent:a-db"
    assert by_name["host_ip"] in (DB_1, DB_2, DB_3)
    assert client.get("/api/v1/entity/nobody-here").json()["host_key"] is None


def test_the_dossier_of_one_address_lists_the_machines_other_keys(client: TestClient) -> None:
    _two_machines(client)

    body = client.get(f"/api/v1/dossiers/{DB_2}").json()

    assert body["ip"] == DB_2
    assert {DB_1, DB_3, "db"} <= set(body["aliases"])
    assert WEB not in body["aliases"]
