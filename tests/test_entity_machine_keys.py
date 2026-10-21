"""One machine, one set of counts, whatever key opens it (dogfood 2026-10-19, R4).

The entity page read investigations, hunt findings, leads and observations by
the raw value. The address of a domain controller said "0 investigations, 34
hunt findings, 4 leads", and its name said "7 investigations, 12 hunt findings,
2 leads". Both resolve to one machine. These tests seed one machine with two
addresses and a name, put each record under a different key, and read the
entity page and the Investigations list through the API:

* ``GET /entity/{value}`` counts every record of the machine from any key;
* a value no machine holds keeps the raw-value count;
* ``GET /investigations?entity=`` lists the investigations of every key of the
  machine, with the true total and the true-positive count;
* a user page counts the hunt findings that name the user in the title.
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
from soc_ai.main import create_app
from soc_ai.store import host_dossier as dossier_store
from soc_ai.store import host_machines
from soc_ai.store import hunts as hunt_svc
from soc_ai.store import investigations as inv_svc
from soc_ai.store.host_machines import AgentClaim, cluster_machines
from soc_ai.store.models import EntityObservation, Investigation, Lead

_NOW = datetime.now(UTC).replace(tzinfo=None, microsecond=0)
_PRIMARY = "192.0.2.10"
_SECOND = "192.0.2.11"
_NAME = "web01"
_AGENT = "a-web"
_LONE = "192.0.2.77"
_EXTERNAL = "8.8.4.4"
_USER = "svc-admin"


def _client(settings: Settings) -> Iterator[TestClient]:
    with (
        patch("soc_ai.so_client.elastic.AsyncElasticsearch", return_value=AsyncMock()),
        patch("soc_ai.main.make_auth", return_value=AsyncMock()),
        patch("soc_ai.main.get_settings", return_value=settings),
    ):
        app = create_app()
        with TestClient(app) as client:
            yield client


@pytest.fixture
def client(settings_kratos: Settings) -> Iterator[TestClient]:
    yield from _client(settings_kratos)


def _observation(key: str, fingerprint: str, *, kind: str = "host") -> EntityObservation:
    return EntityObservation(
        entity_kind=kind,
        entity_key=key,
        kind="novel_binding",
        spec_id="profile.logon",
        fingerprint=fingerprint,
        birth_weight=0.4,
        born_at=_NOW - timedelta(hours=5),
        first_seen_at=_NOW - timedelta(days=2),
        source="profile",
        summary="A first logon.",
    )


def _lead(entities: list[list[str]], *, days: int, status: str = "open") -> Lead:
    return Lead(
        status=status,
        entities_json=entities,
        kinds_json=["logon_chain"],
        weight_at_formation=1.0,
        shadow=False,
        formed_at=_NOW - timedelta(days=days),
        updated_at=_NOW - timedelta(days=days),
    )


def _seed(client: TestClient) -> None:
    """One agent machine with two addresses and a name. Each record names the
    machine under a different key."""

    async def _run() -> None:
        maker = client.app.state.db_sessionmaker  # type: ignore[attr-defined]
        async with maker() as db:
            for ip in (_PRIMARY, _SECOND):
                await dossier_store.upsert_host(
                    db,
                    ip,
                    first_seen=_NOW - timedelta(days=30),
                    last_seen=_NOW - timedelta(hours=1),
                    event_count=50,
                    last_built_at=_NOW,
                    build_error=None,
                    now=_NOW,
                )
            await db.commit()
        async with maker() as db:
            facts = await host_machines.load_address_facts(
                db, dns_names={}, now=datetime.now(UTC), min_confidence=0.6, staleness_hours=72
            )
            prior = await host_machines.load_prior(db)
        agent = AgentClaim(
            agent_id=_AGENT,
            name=_NAME,
            os="Windows Server 2022",
            addresses=(_PRIMARY, _SECOND),
            last_report=_NOW,
        )
        clustering = cluster_machines(facts, agents=[agent], leases=[], prior=prior)
        async with maker() as db:
            await host_machines.persist_clustering(db, clustering, facts, now=datetime.now(UTC))

        async with maker() as db:
            # Three investigations, one per key: the primary address as the
            # source, the second address as the destination, the name as the
            # reporting host. Two reach a true positive.
            a = await inv_svc.create(
                db, alert_es_id="ev-a", started_by="t", src_ip=_PRIMARY, dest_ip=_EXTERNAL
            )
            await inv_svc.finalize(db, a.id, status="complete", verdict="true_positive")
            b = await inv_svc.create(
                db, alert_es_id="ev-b", started_by="t", src_ip=_EXTERNAL, dest_ip=_SECOND
            )
            await inv_svc.finalize(db, b.id, status="complete", verdict="true_positive")
            c = await inv_svc.create(
                db, alert_es_id="ev-c", started_by="t", src_ip="198.51.100.5", dest_ip=_EXTERNAL
            )
            await inv_svc.finalize(db, c.id, status="complete", verdict="false_positive")
            c_row = await db.get(Investigation, c.id)
            assert c_row is not None
            c_row.host_name = _NAME.upper()
            # One investigation on an address no machine holds.
            d = await inv_svc.create(
                db, alert_es_id="ev-d", started_by="t", src_ip=_LONE, dest_ip=_EXTERNAL
            )
            await inv_svc.finalize(db, d.id, status="complete", verdict="needs_more_info")
            # NEGATIVE CONTROL: a synth-eval run on the primary address is not
            # the machine's history.
            e = await inv_svc.create(
                db,
                alert_es_id="ev-e",
                started_by="t",
                src_ip=_PRIMARY,
                dest_ip=_EXTERNAL,
                is_synth_eval=True,
            )
            await inv_svc.finalize(db, e.id, status="complete", verdict="true_positive")

            hunt = await hunt_svc.create(db, objective="Hunt for credential theft", started_by="t")
            await hunt_svc.finalize(
                db,
                hunt.id,
                status="complete",
                report={
                    "findings": [
                        {
                            "title": f"Kerberoast by {_USER} from the web host",
                            "detail": "Ticket requests for service accounts.",
                            "severity": "high",
                            "category": "threat",
                            "hosts": [_NAME.upper()],
                        },
                        {
                            "title": "DCSync rights on the second address",
                            "detail": "Replication rights used.",
                            "severity": "high",
                            "category": "threat",
                            "hosts": [_SECOND],
                        },
                        {
                            # NEGATIVE CONTROL: a longer account name that
                            # starts with the user name names another account.
                            "title": f"Logon by {_USER}istrator on another host",
                            "detail": "noise",
                            "severity": "low",
                            "category": "observation",
                            "hosts": ["198.51.100.9"],
                        },
                    ]
                },
            )
            db.add_all(
                [
                    _lead([["host", _PRIMARY]], days=3),
                    _lead([["host", _NAME]], days=4, status="dismissed"),
                    _lead([["host", _SECOND], ["user", _USER]], days=5),
                    # NEGATIVE CONTROL: a user account spelled like the machine
                    # name is a different thing. It joins the name as asked
                    # only, never the addresses of the machine.
                    _lead([["user", _NAME]], days=6),
                    _observation(_SECOND, "fp-1"),
                    _observation(_NAME, "fp-2"),
                    _observation(_PRIMARY, "fp-3"),
                    # NEGATIVE CONTROL: a user observation keyed like the
                    # machine name joins the name as asked only.
                    _observation(_NAME, "fp-4", kind="user"),
                ]
            )
            await db.commit()

    asyncio.run(_run())


@pytest.fixture
def seeded(client: TestClient) -> TestClient:
    _seed(client)
    return client


def _entity(client: TestClient, value: str, **params: str) -> dict[str, Any]:
    response = client.get(f"/api/v1/entity/{value}", params=params)
    assert response.status_code == 200, response.text
    body: dict[str, Any] = response.json()
    return body


def _counts(body: dict[str, Any]) -> tuple[int, int, int, int, int]:
    s = body["summary"]
    return (
        s["investigationCount"],
        s["truePositiveCount"],
        s["huntFindingCount"],
        s["leadCount"],
        s["observationCount"],
    )


def test_every_key_of_one_machine_reads_the_same_counts(seeded: TestClient) -> None:
    """R4-D2: the address view and the name view count one machine."""
    by_primary = _entity(seeded, _PRIMARY)
    by_second = _entity(seeded, _SECOND)
    by_name = _entity(seeded, _NAME)
    by_agent = _entity(seeded, _AGENT)
    # 3 real investigations, 2 true positives, 2 findings, 3 host leads and
    # 3 host observations. The user lead and the user observation keyed
    # "web01" join the name as asked only, so the name view holds them too.
    # The leads panel and the observations panel apply the same rule.
    assert _counts(by_primary) == (3, 2, 2, 3, 3)
    assert _counts(by_second) == (3, 2, 2, 3, 3)
    assert _counts(by_agent) == (3, 2, 2, 3, 3)
    assert _counts(by_name) == (3, 2, 2, 4, 4)
    for body in (by_primary, by_second, by_name, by_agent):
        assert body["host_key"] == f"agent:{_AGENT}"
        assert set(body["machine_keys"]) >= {_PRIMARY, _SECOND, _NAME, _AGENT}
        assert body["host_name"] == _NAME
    # The timeline holds the same records under every key.
    assert {i["link"] for i in by_primary["timeline"]} == {i["link"] for i in by_name["timeline"]}


def test_a_value_no_machine_holds_keeps_the_raw_count(seeded: TestClient) -> None:
    """NEGATIVE CONTROL: no machine, no expansion."""
    body = _entity(seeded, _LONE)
    assert body["host_key"] is None
    assert body["machine_keys"] == [_LONE]
    assert body["summary"]["investigationCount"] == 1
    assert body["summary"]["truePositiveCount"] == 0


def test_a_user_hint_never_expands_to_the_machine(seeded: TestClient) -> None:
    """A user named like the machine reads that key alone."""
    body = _entity(seeded, _NAME, type="user")
    assert body["host_key"] is None
    assert body["machine_keys"] == [_NAME]
    # The host lead and the user lead keyed "web01". The leads on the
    # addresses of the machine stay out.
    assert body["summary"]["leadCount"] == 2


def test_a_user_page_counts_findings_that_name_the_user(seeded: TestClient) -> None:
    """R4-D13: a finding that names the account in its title is on its page."""
    body = _entity(seeded, _USER, type="user")
    assert body["type"] == "user"
    assert body["summary"]["huntFindingCount"] == 1
    titles = [i["title"] for i in body["timeline"] if i["kind"] == "hunt_finding"]
    assert titles == [f"Kerberoast by {_USER} from the web host"]


def test_the_investigations_list_filters_on_every_key_of_the_machine(
    seeded: TestClient,
) -> None:
    """R4-D3: the list link from the host page holds every run of the machine."""
    for key in (_PRIMARY, _NAME, f"agent:{_AGENT}"):
        response = seeded.get("/api/v1/investigations", params={"entity": key, "limit": 2})
        assert response.status_code == 200, response.text
        body = response.json()
        assert body["total"] == 3, key
        assert body["truePositives"] == 2, key
        assert len(body["rows"]) == 2
    # NEGATIVE CONTROL: no entity filter lists every run, the synth one too.
    everything = seeded.get("/api/v1/investigations").json()
    assert everything["total"] == 5
    # A value no machine holds filters on itself.
    lone = seeded.get("/api/v1/investigations", params={"entity": _LONE}).json()
    assert lone["total"] == 1
