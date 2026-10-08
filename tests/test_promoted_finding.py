"""A promoted investigation names the finding it came from (dogfood 2026-10-06 C4).

The page read "Subject: hunt" with six findings and did not mark the one the
analyst promoted. The investigations list read "10.99.0.30 → 10.99.0.40" with
the victim first, because the anchor alert was the server's response.
"""

from __future__ import annotations

import asyncio
from collections.abc import Iterator
from typing import Any
from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient
from soc_ai.api.webui.routes_hunts import promoted_finding_out
from soc_ai.config import Settings
from soc_ai.main import create_app
from soc_ai.store import hunts as hunt_svc
from soc_ai.store.models import Hunt, Investigation

_REPORT: dict[str, Any] = {
    "findings": [
        {"title": "A scan from 10.99.0.40", "category": "threat", "hosts": ["10.99.0.40"]},
        {
            "title": "HTTP service executes id command as root",
            "category": "threat",
            "hosts": ["10.99.0.30"],
        },
    ]
}


def _hunt() -> Hunt:
    return Hunt(
        id="01HUNT", objective="[lead 16] Investigate 10.99.0.30. The lead formed.", report=_REPORT
    )


def _inv(ordinal: int | None, src: str | None, dst: str | None) -> Investigation:
    return Investigation(
        id="01INV",
        alert_es_id="doc-1",
        hunt_id="01HUNT",
        finding_ordinal=ordinal,
        src_ip=src,
        dest_ip=dst,
    )


def test_the_finding_names_its_number_and_the_attacker_to_the_victim() -> None:
    # The anchor is the response: the victim is its source.
    out = promoted_finding_out(_inv(1, "10.99.0.30", "10.99.0.40"), _hunt())
    assert out is not None
    assert out["label"] == "F2"
    assert out["title"] == "HTTP service executes id command as root"
    assert (out["attacker"], out["victim"]) == ("10.99.0.40", "10.99.0.30")
    assert out["huntTitle"] == "Lead 16 hunt: 10.99.0.30"


def test_no_finding_or_no_hunt_gives_none() -> None:
    """Negative controls: a run no finding promoted, and a deleted hunt."""
    assert promoted_finding_out(_inv(None, "a", "b"), _hunt()) is None
    assert promoted_finding_out(_inv(1, "a", "b"), None) is None
    assert promoted_finding_out(_inv(9, "a", "b"), _hunt()) is None
    # A finding that names no end of the flow leaves the attacker out.
    out = promoted_finding_out(_inv(1, "192.0.2.1", "192.0.2.2"), _hunt())
    assert out is not None and (out["attacker"], out["victim"]) == (None, "10.99.0.30")


@pytest.fixture
def client(settings_kratos: Settings) -> Iterator[TestClient]:
    with (
        patch("soc_ai.so_client.elastic.AsyncElasticsearch", return_value=AsyncMock()),
        patch("soc_ai.main.make_auth", return_value=AsyncMock()),
        patch("soc_ai.main.get_settings", return_value=settings_kratos),
    ):
        app = create_app()
        with TestClient(app) as c:
            yield c


def test_the_investigation_api_carries_the_promoted_finding(client: TestClient) -> None:
    async def seed() -> str:
        async with client.app.state.db_sessionmaker() as db:
            hunt = await hunt_svc.create(db, objective="hunt for id", started_by="t")
            await hunt_svc.finalize(db, hunt.id, status="complete", report=_REPORT)
            db.add(
                Investigation(
                    id="01INVPROMOTED",
                    alert_es_id="doc-1",
                    kind="hunt",
                    status="complete",
                    hunt_id=hunt.id,
                    finding_ordinal=1,
                    src_ip="10.99.0.30",
                    dest_ip="10.99.0.40",
                    rule_name="HTTP service executes id command as root",
                )
            )
            await db.commit()
            return hunt.id

    hunt_id = asyncio.run(seed())
    body = client.get("/api/v1/investigations/01INVPROMOTED").json()
    assert body["promotedFinding"] == {
        "ordinal": 1,
        "label": "F2",
        "title": "HTTP service executes id command as root",
        "hosts": ["10.99.0.30"],
        "attacker": "10.99.0.40",
        "victim": "10.99.0.30",
        "huntId": hunt_id,
        "huntTitle": "hunt for id",
        # The page shows the evidence of the finding first (investigation
        # page work, dogfood 2026-10-06 hunting C4).
        "detail": "",
        "citations": [],
    }
