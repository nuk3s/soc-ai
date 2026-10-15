"""GET /api/v1/hunts/totals: the counts of the whole window on the Hunts page.

The Hunts page header said "N hunts · N findings · N in progress" over the
rows of ``GET /hunts``, and that route caps a page at 100 rows. A window with
140 hunts read "100 hunts". The totals route counts every hunt in the same
window, per type, so the header, the section badge and the type chip state
the window and not the page.
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
from soc_ai.store.auth import utcnow
from soc_ai.store.models import Hunt


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


def _threat(title: str) -> dict[str, Any]:
    return {"title": title, "detail": "d", "severity": "high", "hosts": ["10.0.0.5"]}


def _gap(title: str) -> dict[str, Any]:
    return {
        "title": title,
        "detail": "d",
        "severity": "info",
        "hosts": [],
        "category": "visibility_gap",
    }


def _insert(client: TestClient, rows: list[dict[str, Any]]) -> None:
    """Write hunt rows straight to the store, with the columns the test names."""

    async def _go() -> None:
        async with client.app.state.db_sessionmaker() as db:
            for n, row in enumerate(rows):
                db.add(Hunt(id=f"HUNT{n:028d}", objective=f"objective {n}", **row))
            await db.commit()

    asyncio.run(_go())


def _iso(dt: datetime) -> str:
    return dt.replace(tzinfo=UTC).isoformat().replace("+00:00", "Z")


def test_totals_count_the_whole_window_past_the_list_cap(client: TestClient) -> None:
    """140 hunts in the window: the list holds 100, the totals hold 140."""
    now = utcnow()
    rows: list[dict[str, Any]] = []
    # 90 catalog runs, one finding each, none a threat.
    for n in range(90):
        rows.append(
            {
                "kind": "triggered",
                "status": "complete",
                "created_at": now - timedelta(minutes=n + 1),
                "report": {"findings": [_gap("Gap")], "narrative": "x"},
                "findings_count": 1,
                "threat_findings_count": 0,
            }
        )
    # 40 manual hunts, two findings each, one a threat.
    for n in range(40):
        rows.append(
            {
                "kind": "chat",
                "status": "complete",
                "created_at": now - timedelta(hours=2, minutes=n),
                "report": {"findings": [_threat("T"), _gap("G")], "narrative": "x"},
                "findings_count": 2,
                "threat_findings_count": 1,
            }
        )
    # 10 scheduled hunts that run now, with no report yet.
    for n in range(10):
        rows.append(
            {
                "kind": "scheduled",
                "status": "running",
                "created_at": now - timedelta(hours=5, minutes=n),
            }
        )
    # Outside the window: not counted.
    for n in range(5):
        rows.append(
            {
                "kind": "chat",
                "status": "running",
                "created_at": now - timedelta(days=3, minutes=n),
                "report": {"findings": [_threat("Old")], "narrative": "x"},
                "findings_count": 1,
                "threat_findings_count": 1,
            }
        )
    _insert(client, rows)
    since = _iso(now - timedelta(hours=24))

    listed = client.get("/api/v1/hunts", params={"since": since})
    assert listed.status_code == 200
    assert len(listed.json()) == 100  # the cap of the list route

    resp = client.get("/api/v1/hunts/totals", params={"since": since})
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["hunts"] == 140
    assert body["findings"] == 90 + 80
    assert body["threat_findings"] == 40
    assert body["running"] == 10
    assert body["by_kind"]["triggered"] == {
        "hunts": 90,
        "findings": 90,
        "threat_findings": 0,
        "running": 0,
    }
    assert body["by_kind"]["chat"] == {
        "hunts": 40,
        "findings": 80,
        "threat_findings": 40,
        "running": 0,
    }
    assert body["by_kind"]["scheduled"] == {
        "hunts": 10,
        "findings": 0,
        "threat_findings": 0,
        "running": 10,
    }
    assert "lead" not in body["by_kind"]


def test_totals_read_the_report_of_a_row_without_the_count_columns(client: TestClient) -> None:
    """A legacy or demo row holds a report and no count columns. The list row
    counts its findings from the report, so the totals do the same."""
    now = utcnow()
    _insert(
        client,
        [
            {
                "kind": "chat",
                "status": "complete",
                "created_at": now - timedelta(minutes=5),
                "report": {"findings": [_threat("A"), _threat("B"), _gap("C")], "narrative": "x"},
            },
            {
                "kind": "chat",
                "status": "complete",
                "created_at": now - timedelta(minutes=6),
                "report": {"findings": [_threat("D")], "narrative": "x"},
                "findings_count": 1,
                "threat_findings_count": 1,
            },
        ],
    )
    since = _iso(now - timedelta(hours=1))
    listed = client.get("/api/v1/hunts", params={"since": since}).json()
    body = client.get("/api/v1/hunts/totals", params={"since": since}).json()
    assert body["hunts"] == 2
    assert body["findings"] == sum(r["findingCount"] for r in listed) == 4
    assert body["threat_findings"] == sum(r["threatFindingCount"] for r in listed) == 3


def test_totals_honour_until_and_an_empty_window(client: TestClient) -> None:
    now = utcnow()
    _insert(
        client,
        [
            {"kind": "lead", "status": "complete", "created_at": now - timedelta(hours=3)},
            {"kind": "lead", "status": "complete", "created_at": now - timedelta(hours=1)},
        ],
    )
    body = client.get(
        "/api/v1/hunts/totals",
        params={"since": _iso(now - timedelta(hours=4)), "until": _iso(now - timedelta(hours=2))},
    ).json()
    assert body["hunts"] == 1
    assert body["by_kind"]["lead"]["hunts"] == 1

    empty = client.get(
        "/api/v1/hunts/totals",
        params={
            "since": _iso(now - timedelta(days=30, hours=1)),
            "until": _iso(now - timedelta(days=30)),
        },
    ).json()
    assert empty == {
        "hunts": 0,
        "findings": 0,
        "threat_findings": 0,
        "running": 0,
        "by_kind": {},
    }


def test_totals_route_is_not_read_as_a_hunt_id(client: TestClient) -> None:
    """``/hunts/{hunt_id}`` must not answer for ``/hunts/totals``."""
    resp = client.get("/api/v1/hunts/totals")
    assert resp.status_code == 200
    assert "by_kind" in resp.json()
