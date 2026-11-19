"""The reason of the impact guard on a list row (dogfood 2026-11-17, AA3).

Three true positives read "Successful LFI read-back" beside the impact
"Attempted", and no row said why. When the impact guard lowered "succeeded",
the row states the reason in one line. A stored row shows the line only when
its report holds the change of the guard and the change still stands.
"""

from __future__ import annotations

import asyncio
from collections.abc import Iterator
from typing import Any
from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient
from soc_ai.agent.gates import IMPACT_GATE, impact_change_from_audit
from soc_ai.api.webui.routes_investigations import impact_note
from soc_ai.config import Settings
from soc_ai.main import create_app
from soc_ai.store import investigations as inv_svc

NOTE = "Impact: attempted. The report cites no record that proves success."
CHANGE = impact_change_from_audit(
    {IMPACT_GATE: {"original_impact": "succeeded", "settled_impact": "attempted"}}
)


def _report(**over: Any) -> dict[str, Any]:
    return {"verdict": "true_positive", "impact": "attempted", "impact_change": CHANGE, **over}


def test_the_guard_change_gives_the_line() -> None:
    assert CHANGE is not None
    assert impact_note(_report(), "true_positive") == NOTE


def test_a_row_with_no_stored_change_gives_no_line() -> None:
    """NEGATIVE CONTROL. A model that wrote attempted itself gets no reason."""
    assert impact_note(_report(impact_change=None), "true_positive") is None


def test_a_change_that_no_longer_stands_gives_no_line() -> None:
    """NEGATIVE CONTROL. The stored impact differs from the impact of the change."""
    assert impact_note(_report(impact="succeeded"), "true_positive") is None


def test_an_analyst_verdict_or_another_verdict_gives_no_line() -> None:
    assert impact_note(_report(resolution={"verdict": "true_positive"}), "true_positive") is None
    assert impact_note(_report(), "false_positive") is None


@pytest.fixture
def client(settings_kratos: Settings) -> Iterator[TestClient]:
    with (
        patch("soc_ai.so_client.elastic.AsyncElasticsearch", return_value=AsyncMock()),
        patch("soc_ai.main.make_auth", return_value=AsyncMock()),
        patch("soc_ai.main.get_settings", return_value=settings_kratos),
        TestClient(create_app()) as c,
    ):
        yield c


def test_the_list_row_states_the_line(client: TestClient) -> None:
    async def go() -> tuple[str, str]:
        async with client.app.state.db_sessionmaker() as db:  # type: ignore[attr-defined]
            ids = []
            for name, report in (
                ("Successful LFI read-back", _report()),
                ("LFI probe", _report(impact_change=None)),
            ):
                inv = await inv_svc.create(db, alert_es_id=f"a-{name}", started_by="admin")
                await inv_svc.finalize(
                    db,
                    inv.id,
                    status="complete",
                    verdict="true_positive",
                    confidence=0.85,
                    report=report,
                )
                ids.append(str(inv.id))
            return ids[0], ids[1]

    lowered, plain = asyncio.run(go())
    rows = {r["id"]: r for r in client.get("/api/v1/investigations?range=all").json()["rows"]}
    assert rows[lowered]["impactNote"] == NOTE
    assert rows[lowered]["impact"] == "attempted"
    assert rows[plain]["impactNote"] is None
