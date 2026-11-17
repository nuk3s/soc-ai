"""The lead list states the hunt result and the hold (review of 2026-11-12, C5).

hunts.md finding 6: eight production leads waited on a decision. Seven hunts
found no threat, and the one real item read the same as the rest. The list
row had the outcome label and nothing else.
"""

from __future__ import annotations

import asyncio
from collections.abc import Iterator
from typing import Any
from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient
from soc_ai.config import Settings
from soc_ai.main import create_app
from soc_ai.store import hunts as hunt_svc
from soc_ai.store import investigations as inv_svc
from soc_ai.store import leads as leads_store
from soc_ai.store.models import Hunt, Lead

from tests.test_hunt_findings_investigated import _finding


@pytest.fixture
def client(settings_kratos: Settings) -> Iterator[TestClient]:
    fake_es = AsyncMock()
    with (
        patch("soc_ai.so_client.elastic.AsyncElasticsearch", return_value=fake_es),
        patch("soc_ai.main.make_auth", return_value=AsyncMock()),
        patch("soc_ai.main.get_settings", return_value=settings_kratos),
    ):
        app = create_app()
        with TestClient(app) as c:
            yield c


async def _lead(maker: Any, host: str) -> int:
    async with maker() as db:
        lead = Lead(
            status="open",
            entities_json=[["host", host]],
            kinds_json=["alert"],
            weight_at_formation=1.0,
            shadow=False,
        )
        db.add(lead)
        await db.commit()
        await db.refresh(lead)
        return int(lead.id)


async def _run_row(
    maker: Any, hunt_id: str, ordinal: int, *, status: str = "complete", verdict: str | None = None
) -> str:
    async with maker() as db:
        inv = await inv_svc.create(
            db,
            alert_es_id=f"tel-doc-{ordinal + 1:08d}",
            started_by="system:hunt",
            kind="hunt",
            hunt_id=hunt_id,
            finding_ordinal=ordinal,
        )
        await inv_svc.finalize(db, inv.id, status=status, verdict=verdict, confidence=0.82)
        return str(inv.id)


def test_the_lead_row_of_the_lead_66_shape_states_the_hunt_result_and_the_hold(
    client: TestClient,
) -> None:
    """One true positive, one failed run, one false positive. The lead waits.

    A missing verdict is no grid failure of the hunt, and it still holds the
    lead: the finding that nobody judged can be the threat, and the lead
    closes on verdicts only when each finding has one. The row now states the
    count and the confirmed threat, so it does not read as a benign lead.
    """
    maker = client.app.state.db_sessionmaker
    findings = [_finding(n, hosts=[f"192.0.2.{n}"], detail=f"Host 192.0.2.{n}.") for n in (1, 2, 3)]

    async def seed() -> int:
        lead_id = await _lead(maker, "192.0.2.1")
        async with maker() as db:
            hunt = await hunt_svc.create(
                db, objective="hunt", started_by="auto-hunt", kind="lead", lead_id=lead_id
            )
            hunt_id = hunt.id
        runs = [
            await _run_row(maker, hunt_id, 0, verdict="true_positive"),
            await _run_row(maker, hunt_id, 1, status="error"),
            await _run_row(maker, hunt_id, 2, verdict="false_positive"),
        ]
        async with maker() as db:
            await hunt_svc.finalize(
                db,
                hunt_id,
                status="complete",
                narrative="Suspicious, not confirmed malicious. The sweep hit 15 hosts.",
                report={"findings": findings},
                finding_plan={
                    str(i): hunt_svc.plan_entry("ended", investigation_id=r, origin="opened")
                    for i, r in enumerate(runs)
                },
            )
            await leads_store.mark_hunting(db, lead_id, hunt_id=hunt_id)
            row = await db.get(Hunt, hunt_id)
            assert row is not None
            assert await leads_store.settle_after_hunt(db, row) == "waits"
        return lead_id

    lead_id = asyncio.run(seed())
    rows = client.get("/api/v1/leads", params={"status": "needs_decision"}).json()
    row = next(r for r in rows if r["id"] == lead_id)
    assert row["status"] == "hunting" and row["hunt_status"] == "complete"
    assert row["hunt_answer"] == "Suspicious, not confirmed malicious."
    assert row["hold_reason"] == "no_verdict"
    assert row["hold_sentence"] == (
        "1 of 3 threat findings has no verdict. 1 finding is a true positive."
    )
    detail = client.get(f"/api/v1/hunts/leads/{lead_id}").json()
    assert detail["hold_sentence"] == row["hold_sentence"]
    assert detail["hunt_answer"] == row["hunt_answer"]


def test_the_lead_row_of_a_clean_hunt_states_its_answer_and_its_gap(client: TestClient) -> None:
    """A lead that the analyst reopened waits with a clean hunt. The row says what it found."""
    maker = client.app.state.db_sessionmaker
    gap = {
        "title": "No endpoint agent on the host",
        "category": "visibility_gap",
        "severity": "low",
        "detail": "The host ships no process telemetry. The hunt read the network records.",
    }

    async def seed() -> tuple[int, int]:
        waiting = await _lead(maker, "192.0.2.21")
        fresh = await _lead(maker, "192.0.2.22")
        async with maker() as db:
            hunt = await hunt_svc.create(
                db, objective="hunt", started_by="ann", kind="lead", lead_id=waiting
            )
            await hunt_svc.finalize(
                db,
                hunt.id,
                status="complete",
                narrative="No malicious indication on the host. The traffic is a backup job.",
                report={"findings": [gap]},
            )
            lead = await db.get(Lead, waiting)
            assert lead is not None
            lead.hunt_id = hunt.id
            await db.commit()
        return waiting, fresh

    waiting, fresh = asyncio.run(seed())
    rows = {r["id"]: r for r in client.get("/api/v1/leads", params={"status": "all"}).json()}
    assert rows[waiting]["hunt_answer"] == "No malicious indication on the host."
    assert rows[waiting]["hunt_not_checked"] == [
        "No endpoint agent on the host. The host ships no process telemetry."
    ]
    assert rows[waiting]["hold_reason"] is None and rows[waiting]["hold_sentence"] is None
    # NEGATIVE CONTROL. A lead with no hunt states no result.
    assert rows[fresh]["hunt_answer"] == "" and rows[fresh]["hunt_not_checked"] == []
    assert rows[fresh]["hold_reason"] is None


def test_a_hit_row_names_the_machine_of_its_address(client: TestClient) -> None:
    """C8. The hit is on a container address of mainsrv. The row names mainsrv.

    hunts.md finding 5: 233 unread rows on 73 addresses were 44 machines, and
    the row named the address alone. The console groups by the machine key.
    """
    from datetime import UTC, datetime

    from soc_ai.hunting.leads import content_fingerprint, record_observation
    from soc_ai.hunting.weight import Kind
    from soc_ai.store.models import HostDossier, HostMachine

    maker = client.app.state.db_sessionmaker

    async def seed() -> None:
        async with maker() as db:
            machine = HostMachine(
                machine_key="agent:mainsrv",
                name="mainsrv",
                name_source="agent",
                names_json=[{"value": "mainsrv", "source": "agent"}],
                primary_ip="192.0.2.75",
                agent_id="mainsrv",
                agent_name="mainsrv",
                address_count=1,
                container_count=1,
            )
            db.add(machine)
            await db.flush()
            db.add(
                HostDossier(
                    host_key="192.0.2.75",
                    ip="192.0.2.75",
                    machine_id=machine.id,
                    address_kind="agent",
                )
            )
            db.add(
                HostDossier(
                    host_key="172.18.0.9",
                    ip="172.18.0.9",
                    machine_id=machine.id,
                    address_kind="container",
                )
            )
            await db.commit()
            for key in ("172.18.0.9", "mainsrv", "192.0.2.200"):
                await record_observation(
                    db,
                    entity_kind="host",
                    entity_key=key,
                    kind=Kind.ABOVE_BASELINE,
                    spec_id="profile-connection-rate-spiked",
                    fingerprint=content_fingerprint("connection_rate", "weekday-evening"),
                    summary="The connection rate is 341 per hour.",
                    evidence={"sample_ids": [f"doc-{key}"]},
                    source="profile",
                    shadow=True,
                    now=datetime.now(UTC),
                    statistic="residual_z",
                    statistic_value=4.0,
                )

    asyncio.run(seed())
    hits = client.get("/api/v1/hunts/hits", params={"filter": "shadow"}).json()["hits"]
    by_key = {h["entity_key"]: (h["machine_key"], h["machine_name"]) for h in hits}
    assert by_key == {
        "172.18.0.9": ("agent:mainsrv", "mainsrv"),
        "mainsrv": ("agent:mainsrv", "mainsrv"),
        # NEGATIVE CONTROL. An address on no machine record names no machine.
        "192.0.2.200": (None, None),
    }
    band = client.get("/api/v1/hunts/shadow-hits").json()["hits"]
    assert {h["entity_key"]: h["machine_key"] for h in band} == {
        "172.18.0.9": "agent:mainsrv",
        "mainsrv": "agent:mainsrv",
        "192.0.2.200": None,
    }
    # The read of the hit on one address covers the machine. The same hit on
    # an address of no machine stays unread.
    opened = next(h["id"] for h in hits if h["entity_key"] == "172.18.0.9")
    assert client.post(f"/api/v1/hunts/shadow-hits/{opened}/read").json() == {"ok": True}
    after = client.get("/api/v1/hunts/hits", params={"filter": "shadow"}).json()["hits"]
    assert {h["entity_key"]: h["read"] for h in after} == {
        "172.18.0.9": True,
        "mainsrv": True,
        "192.0.2.200": False,
    }


def test_the_row_of_a_closed_lead_states_the_repeats_that_joined_it(client: TestClient) -> None:
    """A true positive of a rule the closed lead held joins it. The row states the count."""
    from datetime import UTC, datetime, timedelta

    from soc_ai.hunting.sources import observe_alert_verdict

    maker = client.app.state.db_sessionmaker
    now = datetime.now(UTC)

    async def seed() -> int:
        async with maker() as db:
            for alert_id, at in (("a1", now - timedelta(hours=4)), ("a2", now), ("a3", now)):
                out = await observe_alert_verdict(
                    db,
                    alert_id=alert_id,
                    rule_name="ET SCAN Nmap sweep",
                    verdict="true_positive",
                    confidence=0.8,
                    hosts=["10.4.4.40"],
                    now=at,
                )
                if alert_id == "a1":
                    lead_id = out.formed[0]
                    await leads_store.mark_promoted(
                        db, lead_id, investigation_id="01INV", now=now - timedelta(hours=3)
                    )
                else:
                    assert out.formed == ()
            return lead_id

    lead_id = asyncio.run(seed())
    rows = client.get("/api/v1/leads", params={"status": "closed"}).json()
    row = next(r for r in rows if r["id"] == lead_id)
    assert row["repeats_after_close"] == 2
    assert row["last_repeat_at"] == now.replace(tzinfo=None).isoformat() + "Z"
    detail = client.get(f"/api/v1/hunts/leads/{lead_id}").json()
    assert (detail["repeats_after_close"], detail["last_repeat_at"]) == (2, row["last_repeat_at"])
