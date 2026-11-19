"""A lead observation states the event time its investigation holds (AB2).

The lead page read "Recorded 2026-11-11 18:51 UTC. No document time is on
record." for an alert observation whose investigation holds the time of its
event (dogfood 2026-11-17). An alert observation and a hunt finding
observation are written with no document time. The lead payload now reads the
``event_at`` of the investigation behind each one.

The data is synthetic: placeholder addresses and ids.
"""

from __future__ import annotations

import asyncio
from collections.abc import Iterator
from datetime import timedelta
from typing import Any
from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient
from soc_ai.config import Settings
from soc_ai.main import create_app
from soc_ai.store import investigations as inv_svc
from soc_ai.store.auth import utcnow
from soc_ai.store.models import EntityObservation, Lead

_HOST = "192.0.2.41"


@pytest.fixture
def client(settings_kratos: Settings) -> Iterator[TestClient]:
    with (
        patch("soc_ai.so_client.elastic.AsyncElasticsearch", return_value=AsyncMock()),
        patch("soc_ai.main.make_auth", return_value=AsyncMock()),
        patch("soc_ai.main.get_settings", return_value=settings_kratos),
    ):
        app = create_app()
        with TestClient(app) as test_client:
            yield test_client


def _obs(lead_id: int, spec: str, fingerprint: str, **over: Any) -> EntityObservation:
    now = utcnow()
    fields: dict[str, Any] = {
        "entity_kind": "host",
        "entity_key": _HOST,
        "kind": "alert" if spec == "alert" else "hunt_finding",
        "spec_id": spec,
        "fingerprint": fingerprint,
        "birth_weight": 0.9,
        "born_at": now - timedelta(hours=2),
        "first_seen_at": now - timedelta(hours=2),
        "source": spec,
        "lead_id": lead_id,
    }
    fields.update(over)
    return EntityObservation(**fields)


def _seed(client: TestClient) -> dict[str, Any]:
    async def work() -> dict[str, Any]:
        async with client.app.state.db_sessionmaker() as db:
            now = utcnow().replace(microsecond=0)
            event = now - timedelta(days=5)
            finding_event = now - timedelta(days=3)
            # An alert run that holds the time of its alert.
            alert_run = await inv_svc.create(
                db,
                alert_es_id="alert-with-time",
                started_by="t",
                src_ip=_HOST,
                dest_ip="198.51.100.9",
            )
            # NEGATIVE CONTROL: a run whose event time is its creation time
            # holds no event time.
            bare_run = await inv_svc.create(
                db,
                alert_es_id="alert-no-time",
                started_by="t",
                src_ip=_HOST,
                dest_ip="198.51.100.10",
            )
            finding_run = await inv_svc.create(
                db,
                alert_es_id="finding-anchor",
                started_by="t",
                src_ip=_HOST,
                dest_ip="198.51.100.11",
            )
            finding_run.kind = "hunt"
            finding_run.hunt_id = "01HUNTEVENTTIME0000000000A"
            finding_run.finding_ordinal = 2
            for run in (alert_run, bare_run, finding_run):
                run.created_at = now - timedelta(hours=1)
            alert_run.event_at = event
            bare_run.event_at = bare_run.created_at
            finding_run.event_at = finding_event
            lead = Lead(status="open", shadow=False, formed_at=now, entities_json=[["host", _HOST]])
            db.add(lead)
            await db.flush()
            lead_id = int(lead.id)
            rows = {
                "alert": _obs(lead_id, "alert", "alert-with-time"),
                "bare": _obs(lead_id, "alert", "alert-no-time"),
                "finding": _obs(
                    lead_id,
                    "hunt",
                    "finding-fp",
                    evidence_json={"hunt_id": "01HUNTEVENTTIME0000000000A", "ordinal": 2},
                ),
                # A finding of another ordinal names no investigation.
                "other_finding": _obs(
                    lead_id,
                    "hunt",
                    "finding-fp-2",
                    evidence_json={"hunt_id": "01HUNTEVENTTIME0000000000A", "ordinal": 3},
                ),
                # An observation with its own document time keeps it.
                "own": _obs(
                    lead_id,
                    "alert",
                    "alert-with-time-2",
                    observed_at=now - timedelta(days=9),
                ),
            }
            for row in rows.values():
                db.add(row)
            await db.commit()
            return {
                "lead": lead_id,
                "ids": {name: int(row.id) for name, row in rows.items()},
                "event": event,
                "finding_event": finding_event,
                "own": now - timedelta(days=9),
            }

    return asyncio.run(work())


def test_the_lead_page_dates_an_observation_by_its_investigation(client: TestClient) -> None:
    seeded = _seed(client)
    body = client.get(f"/api/v1/hunts/leads/{seeded['lead']}").json()
    by_id = {int(o["id"]): o for o in body["observations"]}
    ids = seeded["ids"]

    def day(o: dict[str, Any]) -> str | None:
        return o["observed_at"][:16] if o["observed_at"] else None

    assert day(by_id[ids["alert"]]) == seeded["event"].isoformat()[:16]
    assert day(by_id[ids["finding"]]) == seeded["finding_event"].isoformat()[:16]
    assert day(by_id[ids["own"]]) == seeded["own"].isoformat()[:16]
    # NEGATIVE CONTROLS: no event time on record keeps the "No document
    # time" line.
    assert by_id[ids["bare"]]["observed_at"] is None
    assert by_id[ids["other_finding"]]["observed_at"] is None
