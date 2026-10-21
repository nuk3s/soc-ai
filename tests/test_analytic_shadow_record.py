"""The shadow record an approval is taken on (dogfood 2026-10-06 W9).

An analytic went live after 0 sweeps. The approve box asked for a reason and
nothing else, and the drawer of a shipped shadow analytic named no end of the
shadow week. The detail route now sends the shadow start, the end of the week,
and the sweeps and hits since the start.
"""

from __future__ import annotations

import asyncio
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient
from soc_ai.config import Settings
from soc_ai.main import create_app
from soc_ai.store import analytics as analytics_store
from soc_ai.store.models import EntityObservation, HuntSpecSweep

from tests.test_analytics_store import SPEC_TEXT

_LOCAL = "local-svc-ticket-from-workstation"


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


def _sweep(at: datetime) -> HuntSpecSweep:
    return HuntSpecSweep(
        spec_id=_LOCAL, created_at=at, shadow=True, window_since="now-24h", window_until="now"
    )


def _seed(client: TestClient, *, shadow_days_ago: int) -> datetime:
    now = datetime.now(UTC).replace(tzinfo=None)
    start = now - timedelta(days=shadow_days_ago)

    async def go() -> None:
        async with client.app.state.db_sessionmaker() as db:
            await analytics_store.create_local(
                db, spec_text=SPEC_TEXT, by="analyst", now=start - timedelta(hours=1)
            )
            await analytics_store.transition(
                db, _LOCAL, to_status="shadow", by="analyst", why="try it", now=start
            )
            # One sweep before the shadow began. It is no part of the record.
            db.add(_sweep(start - timedelta(hours=2)))
            db.add(_sweep(start + timedelta(hours=1)))
            db.add(_sweep(start + timedelta(hours=2)))
            db.add(
                EntityObservation(
                    entity_kind="host",
                    entity_key="10.1.2.3",
                    kind="catalog_match",
                    spec_id=_LOCAL,
                    fingerprint="f1",
                    born_at=start + timedelta(hours=1),
                    first_seen_at=start + timedelta(hours=1),
                    shadow=True,
                    source="catalog",
                )
            )
            await db.commit()

    asyncio.run(go())
    return start


def test_a_shadow_analytic_carries_its_record_and_its_week(client: TestClient) -> None:
    start = _seed(client, shadow_days_ago=2)
    detail = client.get(f"/api/v1/analytics/{_LOCAL}").json()
    assert detail["status"] == "shadow"
    assert detail["shadow_sweeps"] == 2
    assert detail["shadow_hits"] == 1
    since = datetime.fromisoformat(detail["shadow_since"].replace("Z", "+00:00"))
    ends = datetime.fromisoformat(detail["shadow_ends_at"].replace("Z", "+00:00"))
    assert abs((since.replace(tzinfo=None) - start).total_seconds()) < 1
    assert ends - since == timedelta(days=7)
    # C6: the drawer says how often the loop runs: "every hour".
    assert detail["sweep_interval_minutes"] == 60


def test_a_live_analytic_carries_no_shadow_record(client: TestClient) -> None:
    """Negative control: the record is a fact about the shadow status."""
    _seed(client, shadow_days_ago=9)
    res = client.post(
        f"/api/v1/analytics/{_LOCAL}/status", json={"to": "live", "why": "ok, the hits are real"}
    )
    assert res.status_code == 200, res.text
    detail = client.get(f"/api/v1/analytics/{_LOCAL}").json()
    assert detail["status"] == "live"
    assert detail["shadow_since"] is None
    assert detail["shadow_ends_at"] is None
    assert detail["shadow_sweeps"] is None
