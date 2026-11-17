"""The lead tabs hold every lead (production review 2026-11-12, F1).

47 of 70 leads on production had the status ``fleet_condition``. The console
showed each one as "New" and listed it in no tab, because GET /leads refused
the status as a filter. These tests pin the filter, and they pin the sum: the
four tabs hold every lead that the All tab holds.
"""

from __future__ import annotations

import asyncio
from collections.abc import Iterator
from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient
from soc_ai.config import Settings
from soc_ai.main import create_app
from soc_ai.store.models import Hunt, Lead

# The four tabs of the leads block that hold one state each. The fifth tab is
# All.
_TABS = ("needs_decision", "in_progress", "closed", "fleet_condition")


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
    client: TestClient,
    *,
    status: str,
    hunt_status: str | None = None,
    shadow: bool = False,
    scope_count: int = 1,
) -> int:
    """One lead row, with a hunt attached when ``hunt_status`` names one."""

    async def go() -> int:
        async with client.app.state.db_sessionmaker() as db:
            lead = Lead(
                status=status,
                entities_json=[["host", "10.1.2.3"]],
                kinds_json=["above_baseline"],
                shadow=shadow,
                scope_count=scope_count,
            )
            db.add(lead)
            await db.flush()
            if hunt_status is not None:
                hunt = Hunt(
                    id=f"hunt-of-lead-{lead.id}",
                    objective="look at this lead",
                    objective_hash="x",
                    started_by="admin",
                    kind="lead",
                    status=hunt_status,
                )
                db.add(hunt)
                lead.hunt_id = hunt.id
            await db.commit()
            return int(lead.id)

    return asyncio.run(go())


def _auto_hunt(client: TestClient, on: bool) -> None:
    client.app.state.settings = client.app.state.settings.model_copy(update={"lead_auto_hunt": on})


def _ids(client: TestClient, status: str) -> set[int]:
    res = client.get(f"/api/v1/leads?status={status}&limit=200")
    assert res.status_code == 200, res.text
    return {int(lead["id"]) for lead in res.json()}


def _count(client: TestClient, status: str) -> int:
    res = client.get(f"/api/v1/leads/count?status={status}")
    assert res.status_code == 200, res.text
    return int(res.json()["total"])


def _seed_every_state(client: TestClient) -> dict[str, int]:
    return {
        "untouched": _seed(client, status="open"),
        "shadow": _seed(client, status="open", shadow=True),
        "hunted": _seed(client, status="hunting", hunt_status="complete"),
        "failed": _seed(client, status="hunting", hunt_status="error"),
        "running": _seed(client, status="hunting", hunt_status="running"),
        "dismissed": _seed(client, status="dismissed"),
        "promoted": _seed(client, status="promoted"),
        "fleet": _seed(client, status="fleet_condition", scope_count=34),
        "fleet_shadow": _seed(client, status="fleet_condition", shadow=True, scope_count=43),
    }


def test_a_fleet_condition_lead_has_its_own_filter(client: TestClient) -> None:
    ids = _seed_every_state(client)

    assert _ids(client, "fleet_condition") == {ids["fleet"], ids["fleet_shadow"]}
    assert _count(client, "fleet_condition") == 2
    rows = {int(r["id"]): r for r in client.get("/api/v1/leads?status=fleet_condition").json()}
    assert rows[ids["fleet"]]["status"] == "fleet_condition"
    assert rows[ids["fleet"]]["scope_count"] == 34


@pytest.mark.parametrize("auto_hunt", [False, True])
def test_a_fleet_condition_lead_waits_on_no_decision(client: TestClient, auto_hunt: bool) -> None:
    """NEGATIVE CONTROL. The new tab takes the lead from no other tab's rule.

    A fleet condition lead is in the Needs decision tab under neither
    setting, and the Needs-you count does not hold it. A shadow one too: the
    shadow flag puts an open lead in Needs decision, and it must not put a
    fleet condition there.
    """
    ids = _seed_every_state(client)
    _auto_hunt(client, auto_hunt)

    for status in ("needs_decision", "in_progress", "closed", "open", "new", "open_or_hunting"):
        listed = _ids(client, status)
        assert ids["fleet"] not in listed, status
        assert ids["fleet_shadow"] not in listed, status
    needs_you = client.get("/api/v1/hunts/needs-you").json()
    assert needs_you["leads_needing_decision"] == _count(client, "needs_decision")


def test_the_four_tabs_hold_every_lead_with_the_loop_off(client: TestClient) -> None:
    """With auto-hunt off, the four tabs are a partition of the All tab."""
    ids = _seed_every_state(client)
    _auto_hunt(client, False)

    every = _ids(client, "all")
    assert every == set(ids.values())
    tabs = {tab: _ids(client, tab) for tab in _TABS}
    assert set().union(*tabs.values()) == every
    assert sum(len(rows) for rows in tabs.values()) == len(every)
    assert sum(_count(client, tab) for tab in _TABS) == _count(client, "all")


def test_with_the_loop_on_only_a_queued_lead_is_outside_the_four_tabs(
    client: TestClient,
) -> None:
    """A new lead that waits on auto-hunt is the one lead no tab holds.

    The console prints that count beside the tabs. The lead carries
    ``hunt_queued``, so the count and the pill come from one rule.
    """
    ids = _seed_every_state(client)
    _auto_hunt(client, True)

    every = {int(r["id"]): r for r in client.get("/api/v1/leads?status=all").json()}
    in_a_tab = set().union(*(_ids(client, tab) for tab in _TABS))
    outside = set(every) - in_a_tab
    assert outside == {ids["untouched"]}
    assert all(every[i]["hunt_queued"] is True for i in outside)
    assert all(every[i]["hunt_queued"] is False for i in in_a_tab)
    assert _count(client, "all") - sum(_count(client, tab) for tab in _TABS) == len(outside)


def test_an_unknown_status_is_still_refused(client: TestClient) -> None:
    """NEGATIVE CONTROL. The filter list grew by one value and by no more."""
    res = client.get("/api/v1/leads?status=fleet")
    assert res.status_code == 422
    assert res.json()["detail"]["reason"] == "bad_filter"
    assert "fleet_condition" in res.json()["detail"]["hint"]
