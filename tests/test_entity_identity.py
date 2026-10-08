"""The entity page answers "who is this and should I worry" (dogfood 2026-10-06).

An investigation named a host, an account and an external address, and none
of them was a link. The palette found an account named in a live lead, a
domain and a hunt id nowhere. These tests drive the real app on a scratch
database and read the answers through the API:

* ``GET /entity/{value}`` says what the value is, counts the leads and
  observations that name it, and gives the first and last time soc-ai saw it;
* ``GET /search/entities`` finds users, domains, addresses no machine holds
  and hunts;
* the investigation page receives each entity it names with its link.
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
from soc_ai.store.models import EntityObservation, Lead

_NOW = datetime.now(UTC).replace(tzinfo=None, microsecond=0)
_EXTERNAL = "8.8.4.4"
_INTERNAL_NO_MACHINE = "10.70.0.226"


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


def _seed(client: TestClient) -> dict[str, Any]:
    """One agent machine joined to a domain, a lead on an account, an
    observation on the account, an investigation from the machine to an
    external address and a finished hunt."""

    async def _run() -> dict[str, Any]:
        maker = client.app.state.db_sessionmaker  # type: ignore[attr-defined]
        async with maker() as db:
            await dossier_store.upsert_host(
                db,
                "10.40.0.20",
                first_seen=_NOW - timedelta(days=30),
                last_seen=_NOW - timedelta(hours=1),
                event_count=50,
                last_built_at=_NOW,
                build_error=None,
                now=_NOW,
            )
            await db.commit()
        async with maker() as db:
            await dossier_store.set_override(db, "10.40.0.20", "domain_membership", "corp.example")
        async with maker() as db:
            facts = await host_machines.load_address_facts(
                db,
                dns_names={},
                now=datetime.now(UTC),
                min_confidence=0.6,
                staleness_hours=72,
            )
            prior = await host_machines.load_prior(db)
        agent = AgentClaim(
            agent_id="a-dc",
            name="dc01",
            os="Windows Server 2022",
            addresses=("10.40.0.20",),
            last_report=_NOW,
        )
        clustering = cluster_machines(facts, agents=[agent], leases=[], prior=prior)
        async with maker() as db:
            await host_machines.persist_clustering(db, clustering, facts, now=datetime.now(UTC))
        async with maker() as db:
            lead = Lead(
                status="open",
                entities_json=[["user", "svc-backup"], ["host", "10.40.0.20"]],
                kinds_json=["logon_chain"],
                weight_at_formation=1.2,
                shadow=False,
                formed_at=_NOW - timedelta(days=3),
                updated_at=_NOW - timedelta(days=1),
            )
            closed = Lead(
                status="dismissed",
                entities_json=[["user", "svc-backup"]],
                kinds_json=["off_hours"],
                weight_at_formation=1.0,
                shadow=False,
                formed_at=_NOW - timedelta(days=9),
                updated_at=_NOW - timedelta(days=8),
            )
            db.add_all([lead, closed])
            await db.flush()
            db.add(
                EntityObservation(
                    entity_kind="user",
                    entity_key="svc-backup",
                    kind="novel_binding",
                    spec_id="profile.logon",
                    fingerprint="fp-1",
                    birth_weight=0.4,
                    born_at=_NOW - timedelta(hours=5),
                    first_seen_at=_NOW - timedelta(days=4),
                    source="profile",
                    summary="First logon on dc01.",
                )
            )
            await db.commit()
            lead_id = lead.id
        async with maker() as db:
            inv = await inv_svc.create(
                db,
                alert_es_id="ev-1",
                started_by="t",
                src_ip="10.40.0.20",
                dest_ip=_EXTERNAL,
                rule_name="Outbound to rare address",
            )
            await inv_svc.finalize(db, inv.id, status="complete", verdict="true_positive")
            other = await inv_svc.create(
                db,
                alert_es_id="ev-2",
                started_by="t",
                src_ip=_INTERNAL_NO_MACHINE,
                dest_ip="10.40.0.20",
                rule_name="SSH login failure",
            )
            await inv_svc.finalize(db, other.id, status="complete", verdict="needs_more_info")
            hunt = await hunt_svc.create(
                db, objective="Hunt for backup account abuse", started_by="t"
            )
            await hunt_svc.finalize(db, hunt.id, status="complete", report={"findings": []})
            await db.commit()
            return {"lead_id": lead_id, "inv_id": inv.id, "hunt_id": hunt.id}

    return asyncio.run(_run())


@pytest.fixture
def seeded(client: TestClient) -> tuple[TestClient, dict[str, Any]]:
    return client, _seed(client)


def _entity(client: TestClient, value: str, **params: str) -> dict[str, Any]:
    response = client.get(f"/api/v1/entity/{value}", params=params)
    assert response.status_code == 200, response.text
    body: dict[str, Any] = response.json()
    return body


# ---------------------------------------------------------------------------
# What the value is
# ---------------------------------------------------------------------------


def test_an_account_named_by_a_lead_is_a_user(seeded: tuple[TestClient, dict[str, Any]]) -> None:
    client, _ = seeded
    body = _entity(client, "svc-backup")
    assert body["type"] == "user"
    assert body["summary"]["leadCount"] == 2
    assert body["summary"]["openLeadCount"] == 1
    assert body["summary"]["observationCount"] == 1
    # The first sighting is the older lead, the last is the observation.
    assert body["first_seen"] is not None and body["last_seen"] is not None
    assert body["first_seen"] < body["last_seen"]
    assert body["host_key"] is None


def test_an_address_outside_the_internal_ranges_is_external(
    seeded: tuple[TestClient, dict[str, Any]],
) -> None:
    client, _ = seeded
    body = _entity(client, _EXTERNAL)
    assert body["type"] == "external_address"
    assert body["summary"]["investigationCount"] == 1
    assert body["summary"]["truePositiveCount"] == 1
    assert body["host_key"] is None


def test_an_internal_address_no_machine_holds_stays_an_address(
    seeded: tuple[TestClient, dict[str, Any]],
) -> None:
    """Dogfood 2026-10-06: an address an investigation named had no Hosts row."""
    client, _ = seeded
    body = _entity(client, _INTERNAL_NO_MACHINE)
    assert body["type"] == "address"
    assert body["host_key"] is None
    assert body["summary"]["investigationCount"] == 1


def test_a_machine_name_is_a_host_with_its_key(seeded: tuple[TestClient, dict[str, Any]]) -> None:
    client, _ = seeded
    body = _entity(client, "dc01")
    assert body["type"] == "host"
    assert body["host_key"] == "agent:a-dc"
    # NEGATIVE CONTROL: the user hint never opens a machine of the same name.
    hinted = _entity(client, "dc01", type="user")
    assert hinted["type"] == "user"
    assert hinted["host_key"] is None


def test_a_name_machines_are_joined_to_is_a_domain(
    seeded: tuple[TestClient, dict[str, Any]],
) -> None:
    client, _ = seeded
    body = _entity(client, "corp.example")
    assert body["type"] == "domain"
    assert body["domain_machines"] == 1


def test_a_name_nothing_records_says_nothing_is_known(client: TestClient) -> None:
    """NEGATIVE CONTROL: no lead, observation, investigation or machine."""
    body = _entity(client, "nobody-here")
    assert body["type"] == "name"
    assert body["first_seen"] is None
    assert body["last_seen"] is None
    assert body["summary"]["leadCount"] == 0
    assert body["summary"]["observationCount"] == 0


# ---------------------------------------------------------------------------
# The palette search
# ---------------------------------------------------------------------------


def _hits(client: TestClient, q: str) -> list[dict[str, Any]]:
    response = client.get("/api/v1/search/entities", params={"q": q})
    assert response.status_code == 200, response.text
    hits: list[dict[str, Any]] = response.json()["hits"]
    return hits


def test_the_palette_finds_a_user_a_domain_and_a_hunt(
    seeded: tuple[TestClient, dict[str, Any]],
) -> None:
    client, ids = seeded
    users = _hits(client, "backup")
    assert any(h["type"] == "user" and h["value"] == "svc-backup" for h in users)
    user = next(h for h in users if h["type"] == "user")
    assert user["href"] == "/entity/svc-backup?type=user"
    assert user["detail"]
    domains = _hits(client, "corp.ex")
    assert [h["value"] for h in domains if h["type"] == "domain"] == ["corp.example"]
    hunt_hits = _hits(client, ids["hunt_id"][-8:].lower())
    assert [h["value"] for h in hunt_hits if h["type"] == "hunt"] == [ids["hunt_id"]]
    assert hunt_hits[0]["href"] == f"/hunts/{ids['hunt_id']}"


def test_the_palette_offers_an_address_no_machine_holds(
    seeded: tuple[TestClient, dict[str, Any]],
) -> None:
    client, _ = seeded
    external = _hits(client, _EXTERNAL)
    assert [(h["type"], h["href"]) for h in external] == [
        ("external_address", f"/entity/{_EXTERNAL}")
    ]
    # NEGATIVE CONTROL: an address a machine holds is the Hosts search's answer.
    held = _hits(client, "10.40.0.20")
    assert all(h["value"] != "10.40.0.20" for h in held)


def test_two_hits_never_read_the_same(seeded: tuple[TestClient, dict[str, Any]]) -> None:
    client, _ = seeded
    hits = _hits(client, "10.")
    pairs = [(h["label"], h["detail"]) for h in hits]
    assert len(pairs) == len(set(pairs))


def test_a_short_query_answers_no_hits(seeded: tuple[TestClient, dict[str, Any]]) -> None:
    """NEGATIVE CONTROL: one character would match nearly everything."""
    client, _ = seeded
    assert _hits(client, "s") == []


# ---------------------------------------------------------------------------
# The investigation names its entities
# ---------------------------------------------------------------------------


def test_the_investigation_names_each_entity_with_its_link(
    seeded: tuple[TestClient, dict[str, Any]],
) -> None:
    client, ids = seeded
    response = client.get(f"/api/v1/investigations/{ids['inv_id']}")
    assert response.status_code == 200, response.text
    entities = {e["value"]: e for e in response.json()["entities"]}
    assert entities["10.40.0.20"]["type"] == "address"
    assert entities["10.40.0.20"]["host_key"] == "agent:a-dc"
    assert entities["10.40.0.20"]["href"] == "/hosts/agent%3Aa-dc"
    assert entities["10.40.0.20"]["role"] == "source"
    assert entities[_EXTERNAL]["type"] == "external_address"
    assert entities[_EXTERNAL]["href"] == f"/entity/{_EXTERNAL}"
    assert entities[_EXTERNAL]["role"] == "destination"


def test_a_promoted_lead_adds_its_user(seeded: tuple[TestClient, dict[str, Any]]) -> None:
    client, ids = seeded

    async def _promote() -> str:
        maker = client.app.state.db_sessionmaker  # type: ignore[attr-defined]
        async with maker() as db:
            inv = await inv_svc.create(
                db,
                alert_es_id="lead-1",
                started_by="t",
                subject={
                    "type": "hunt",
                    "hunt_id": ids["hunt_id"],
                    "objective": "Lead",
                    "finding_ordinals": [],
                    "lead_id": ids["lead_id"],
                    "document_ids": [],
                    "observation_ids": [],
                },
            )
            await db.commit()
            return inv.id

    inv_id = asyncio.run(_promote())
    entities = client.get(f"/api/v1/investigations/{inv_id}").json()["entities"]
    user = next(e for e in entities if e["value"] == "svc-backup")
    assert user == {
        "value": "svc-backup",
        "type": "user",
        "role": "lead",
        "host_key": None,
        "href": "/entity/svc-backup?type=user",
    }


def test_the_observation_carries_its_alert_verdict(client: TestClient) -> None:
    """The host page counts the alert verdicts of the last seven days."""

    async def _run() -> None:
        maker = client.app.state.db_sessionmaker  # type: ignore[attr-defined]
        async with maker() as db:
            db.add_all(
                [
                    EntityObservation(
                        entity_kind="host",
                        entity_key="10.40.0.30",
                        kind="alert",
                        spec_id="alert",
                        fingerprint="alert-1",
                        birth_weight=1.0,
                        born_at=_NOW - timedelta(days=1),
                        first_seen_at=_NOW - timedelta(days=1),
                        source="alert",
                        evidence_json={"verdict": "true_positive", "confidence": 0.7},
                        summary="Rule: true positive at 0.70",
                    ),
                    EntityObservation(
                        entity_kind="host",
                        entity_key="10.40.0.30",
                        kind="novel_served_port",
                        spec_id="profile.ports",
                        fingerprint="port-1",
                        birth_weight=0.3,
                        born_at=_NOW - timedelta(days=2),
                        first_seen_at=_NOW - timedelta(days=2),
                        source="profile",
                        evidence_json={"verdict": "true_positive"},
                    ),
                ]
            )
            await db.commit()

    asyncio.run(_run())
    rows = client.get("/api/v1/hunts/observations", params={"entity": "10.40.0.30"}).json()[
        "observations"
    ]
    by_source = {row["source"]: row for row in rows}
    assert by_source["alert"]["verdict"] == "true_positive"
    # NEGATIVE CONTROL: a profile row with a stray key is not a verdict.
    assert by_source["profile"]["verdict"] is None


def test_the_dossier_states_whether_profiles_run(client: TestClient) -> None:
    body = client.get("/api/v1/dossiers/10.40.0.99").json()
    assert body["profiles_enabled"] in (True, False)
