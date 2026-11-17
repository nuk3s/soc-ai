"""The hunt page names the campaign that holds a finding (H6).

A finding that a campaign holds reads ``investigationStatus`` "campaign" and
carries ``campaign``: the campaign link that the other pages use. A merged
campaign answers with the campaign it merged into. A withdrawn campaign holds
nothing: the finding then reads no investigation, and the card offers its own
run. The Objective step shows the campaign blocks that the hunt read.

The data is synthetic: TEST-NET addresses and placeholder names.
"""

from __future__ import annotations

import asyncio
from collections.abc import Iterator
from datetime import UTC, datetime
from typing import Any
from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient
from soc_ai.api.webui.routes_hunts import _objective_detail
from soc_ai.config import Settings
from soc_ai.hunting import campaign_block, campaign_hold
from soc_ai.main import create_app
from soc_ai.store import hunts as hunt_svc
from soc_ai.store.models import Campaign

from tests.test_hunt_campaign_block import seed_campaign

LINK_KEYS = {"id", "title", "status", "stage", "differs", "decision"}


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


def _seed(
    client: TestClient, *, status: str = "active", merged_into: bool = False
) -> dict[str, Any]:
    """A complete hunt with one held finding and one finding with no entry."""
    maker = client.app.state.db_sessionmaker  # type: ignore[attr-defined]

    async def _go() -> dict[str, Any]:
        at = datetime.now(UTC).replace(tzinfo=None, microsecond=0)
        held_id = await seed_campaign(maker, last=at, seed="held")
        survivor = await seed_campaign(maker, last=at, seed="survivor", title="survivor")
        async with maker() as db:
            row = await db.get(Campaign, held_id)
            assert row is not None
            row.status = "merged" if merged_into else status
            row.merged_into_id = survivor if merged_into else None
            hunt = await hunt_svc.create(db, objective="hunt", started_by="admin")
            findings = [
                {
                    "title": "File read",
                    "detail": "d",
                    "category": "threat",
                    "hosts": ["192.0.2.164"],
                },
                {"title": "Note", "detail": "d", "category": "observation", "hosts": []},
            ]
            await hunt_svc.finalize(
                db,
                hunt.id,
                status="complete",
                narrative="n",
                report={"findings": findings, "narrative": "n"},
                finding_plan={
                    "0": hunt_svc.plan_entry(
                        hunt_svc.LINK_CAMPAIGN,
                        reason=campaign_hold.HELD_REASON,
                        campaign_id=held_id,
                    )
                },
            )
            await db.commit()
            return {"hunt": hunt.id, "held": held_id, "survivor": survivor}

    return asyncio.run(_go())


def test_a_held_finding_reads_the_state_campaign_and_carries_the_campaign_link(
    client: TestClient,
) -> None:
    seeded = _seed(client)

    body = client.get(f"/api/v1/hunts/{seeded['hunt']}").json()

    held, other = body["findings"]
    assert held["investigationStatus"] == "campaign"
    assert set(held["campaign"]) == LINK_KEYS
    assert held["campaign"]["id"] == seeded["held"]
    assert held["campaign"]["status"] == "open"
    assert held["investigationId"] is None
    # Negative control: every other finding carries no campaign.
    assert other["campaign"] is None


def test_a_merged_campaign_answers_with_the_campaign_it_merged_into(client: TestClient) -> None:
    seeded = _seed(client, merged_into=True)

    body = client.get(f"/api/v1/hunts/{seeded['hunt']}").json()

    assert body["findings"][0]["campaign"]["id"] == seeded["survivor"]
    assert body["findings"][0]["investigationStatus"] == "campaign"


def test_a_withdrawn_campaign_holds_nothing(client: TestClient) -> None:
    """Negative control: the finding offers its own run. No work is dropped."""
    seeded = _seed(client, status="withdrawn")

    held = client.get(f"/api/v1/hunts/{seeded['hunt']}").json()["findings"][0]

    assert held["campaign"] is None
    assert held["investigationStatus"] is None


def test_the_objective_step_shows_the_campaign_blocks_the_hunt_read() -> None:
    read = _objective_detail({"objective": "o", "campaigns": "CAMPAIGN BLOCK"})
    dropped = _objective_detail({"objective": "o", "campaigns_dropped": "residue"})

    assert read == "o\n\nCAMPAIGN BLOCK"
    assert dropped == f"o\n\n{campaign_block.DROPPED_SENTENCE}"
    assert _objective_detail({"objective": "o"}) == "o"
