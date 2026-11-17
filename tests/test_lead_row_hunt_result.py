"""The lead list carries the result of the hunt (production review 2026-11-12).

Seven of eight open leads on production waited after a hunt that found no
threat. The lead row stated the outcome on the pill and nothing of what the
hunt said or could not check, so the analyst opened each lead to learn it. The
lead page had both facts. GET /leads now sends them on each row:
``hunt_answer`` and ``hunt_not_checked``.
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
from soc_ai.store import hunts as hunt_svc
from soc_ai.store.models import Hunt, Lead


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


def _seed_lead(client: TestClient, *, status: str = "hunting") -> int:
    async def go() -> int:
        async with client.app.state.db_sessionmaker() as db:
            lead = Lead(
                status=status,
                entities_json=[["host", "10.1.2.3"]],
                kinds_json=["catalog_match"],
                shadow=False,
            )
            db.add(lead)
            await db.commit()
            return int(lead.id)

    return asyncio.run(go())


def _seed_hunt(
    client: TestClient,
    lead_id: int,
    *,
    findings: list[dict[str, Any]],
    narrative: str,
    status: str = "complete",
    hours_ago: float = 2,
    attach: bool = True,
) -> str:
    """One lead hunt. ``attach`` names it on the lead, as a hunt start does."""

    async def go() -> str:
        async with client.app.state.db_sessionmaker() as db:
            hunt = await hunt_svc.create(
                db,
                objective=f"[lead {lead_id}] look at this lead",
                started_by="admin",
                kind="lead",
                starter="lead",
                lead_id=lead_id,
            )
            if status != "running":
                await hunt_svc.finalize(
                    db,
                    hunt.id,
                    status=status,
                    narrative=narrative,
                    report={"findings": findings, "narrative": narrative},
                )
            row = await db.get(Hunt, hunt.id)
            assert row is not None
            # Relative to now. A fixed date leaves every window in time.
            row.created_at = (datetime.now(UTC) - timedelta(hours=hours_ago)).replace(tzinfo=None)
            if attach:
                lead = await db.get(Lead, lead_id)
                assert lead is not None
                lead.hunt_id = hunt.id
            await db.commit()
            return hunt.id

    return asyncio.run(go())


_THREAT = {"title": "HTTP service runs id as root", "category": "threat", "detail": "x"}
_GAP = {
    "title": "Container telemetry",
    "category": "visibility_gap",
    "detail": "The host has no agent. The hunt read the network flows alone.",
}
_NOTE = {"title": "Attribute writes", "category": "observation", "detail": "Two 4662 writes."}


def _row(client: TestClient, lead_id: int, status: str = "all") -> dict[str, Any]:
    rows = client.get(f"/api/v1/leads?status={status}").json()
    return next(r for r in rows if r["id"] == lead_id)


def test_the_lead_row_carries_the_answer_and_the_gaps_of_its_hunt(client: TestClient) -> None:
    lead_id = _seed_lead(client)
    _seed_hunt(
        client,
        lead_id,
        findings=[_NOTE, _GAP],
        narrative="No malicious indication on the host. The flows are DNS lookups.",
    )
    row = _row(client, lead_id)
    assert row["hunt_answer"] == "No malicious indication on the host."
    assert row["hunt_not_checked"] == ["Container telemetry. The host has no agent."]
    # The row and the lead page state one hunt in the same words.
    detail = client.get(f"/api/v1/hunts/leads/{lead_id}").json()
    assert detail["hunts"][0]["answer"] == row["hunt_answer"]
    assert detail["hunts"][0]["not_checked"] == row["hunt_not_checked"]
    assert detail["hunt_answer"] == row["hunt_answer"]
    assert detail["hunt_not_checked"] == row["hunt_not_checked"]


def test_the_row_states_the_hunt_the_lead_names_and_no_earlier_one(client: TestClient) -> None:
    """The lead points at its newest hunt. The pill counts the earlier ones."""
    lead_id = _seed_lead(client)
    _seed_hunt(
        client,
        lead_id,
        findings=[_THREAT],
        narrative="The HTTP service ran id as root.",
        hours_ago=72,
        attach=False,
    )
    _seed_hunt(client, lead_id, findings=[], narrative="No threat is present. Nothing ran.")
    row = _row(client, lead_id)
    assert row["hunt_answer"] == "No threat is present."
    assert row["hunt_not_checked"] == []
    assert row["hunt_count"] == 2 and row["hunt_threat_count"] == 1


@pytest.mark.parametrize("status", ["error", "cancelled", "interrupted"])
def test_a_hunt_that_could_not_run_states_no_answer(client: TestClient, status: str) -> None:
    """NEGATIVE CONTROL. A stopped hunt answered nothing.

    Its narrative is a part of a report, and its gap findings are not what a
    whole hunt could not check. The row must not print either as a result.
    """
    lead_id = _seed_lead(client)
    _seed_hunt(
        client,
        lead_id,
        findings=[_GAP],
        narrative="No malicious indication so far.",
        status=status,
    )
    row = _row(client, lead_id)
    assert row["hunt_outcome"] == "failed"
    assert row["hunt_answer"] == ""
    assert row["hunt_not_checked"] == []


def test_a_running_hunt_and_a_lead_with_no_hunt_state_no_answer(client: TestClient) -> None:
    """NEGATIVE CONTROL. No finished hunt, no answer."""
    running = _seed_lead(client)
    _seed_hunt(client, running, findings=[], narrative="", status="running")
    no_hunt = _seed_lead(client, status="open")
    for lead_id in (running, no_hunt):
        row = _row(client, lead_id)
        assert row["hunt_answer"] == ""
        assert row["hunt_not_checked"] == []
    assert _row(client, no_hunt)["hunt_count"] == 0
