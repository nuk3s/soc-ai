"""The leads of one host, read by the server, with the true total.

The host page read ``GET /leads?status=all``, which answers the newest 50 leads
of the whole estate, and kept the ones that named the host. A host whose leads
were older than the 50 newest overall showed no lead at all, and the hero said
nothing waited on it. The Hunts page heading counted the 50 rows it held, so it
never said more than 50.

``GET /leads`` now takes ``entity`` and filters on the server, under every key
of the entity's machine. ``GET /leads/count`` answers the true total for the
same filter. The negative controls pin the leads that must stay out: another
host's leads, a user account named like the host, and the closed leads under
``open_or_hunting``.
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

from tests.test_host_aliases import _host

HOST = "192.0.2.10"
OTHER = "192.0.2.20"


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


def _ago(days: float) -> datetime:
    """A stored (naive UTC) timestamp that many days back from now."""
    return (datetime.now(UTC) - timedelta(days=days)).replace(tzinfo=None)


def _leads(
    client: TestClient,
    entity: list[str],
    *,
    count: int,
    days_ago: float,
    status: str = "open",
) -> list[int]:
    """``count`` leads on one entity, each formed ``days_ago`` days back."""
    from soc_ai.store.models import Lead

    async def go() -> list[int]:
        async with client.app.state.db_sessionmaker() as db:  # type: ignore[attr-defined]
            rows = [
                Lead(
                    status=status,
                    entities_json=[list(entity)],
                    kinds_json=["catalog_match"],
                    formed_at=_ago(days_ago) + timedelta(seconds=i),
                    shadow=False,
                )
                for i in range(count)
            ]
            db.add_all(rows)
            await db.commit()
            return [int(r.id) for r in rows]

    return asyncio.run(go())


def _list(client: TestClient, query: str) -> list[dict[str, Any]]:
    res = client.get(f"/api/v1/leads?{query}")
    assert res.status_code == 200, res.text
    body: list[dict[str, Any]] = res.json()
    return body


def _count(client: TestClient, query: str) -> int:
    res = client.get(f"/api/v1/leads/count?{query}")
    assert res.status_code == 200, res.text
    return int(res.json()["total"])


# ---------------------------------------------------------------------------
# The host filter
# ---------------------------------------------------------------------------


def test_a_host_keeps_leads_older_than_the_newest_fifty(client: TestClient) -> None:
    """The defect: 55 newer leads elsewhere pushed this host's 3 out of the page."""
    mine = _leads(client, ["host", HOST], count=3, days_ago=20)
    _leads(client, ["host", OTHER], count=55, days_ago=1)

    # The old read: the newest 50 overall hold none of this host's leads.
    overall = _list(client, "status=all")
    assert len(overall) == 50
    assert not {lead["id"] for lead in overall} & set(mine)

    rows = _list(client, f"status=all&entity={HOST}")
    assert sorted(lead["id"] for lead in rows) == sorted(mine)
    assert _count(client, f"status=all&entity={HOST}") == 3


def test_another_hosts_leads_stay_out(client: TestClient) -> None:
    """Negative control: the filter must not pass the leads of a second host."""
    mine = _leads(client, ["host", HOST], count=2, days_ago=3)
    theirs = _leads(client, ["host", OTHER], count=4, days_ago=1)

    rows = _list(client, f"status=all&entity={HOST}")
    ids = {lead["id"] for lead in rows}
    assert ids == set(mine)
    assert not ids & set(theirs)
    assert all(["host", HOST] in lead["entities"] for lead in rows)
    assert _count(client, f"status=all&entity={OTHER}") == 4


def test_the_total_counts_past_the_row_limit(client: TestClient) -> None:
    """The list stops at ``limit``. The count does not."""
    _leads(client, ["host", HOST], count=7, days_ago=2)
    _leads(client, ["host", OTHER], count=60, days_ago=1)

    assert len(_list(client, "status=all")) == 50
    assert _count(client, "status=all") == 67
    rows = _list(client, f"status=all&entity={HOST}&limit=5")
    assert len(rows) == 5
    # Newest first, as the unfiltered list orders them.
    formed = [lead["formed_at"] for lead in rows]
    assert formed == sorted(formed, reverse=True)
    assert _count(client, f"status=all&entity={HOST}") == 7


def test_the_host_filter_reads_every_key_of_the_machine(client: TestClient) -> None:
    """A lead stored under the host name, in any case, belongs to the address."""
    _host(client, HOST, "dc01.example.test")
    by_name = _leads(client, ["host", "DC01"], count=1, days_ago=2)
    by_address = _leads(client, ["host", HOST], count=1, days_ago=2)

    rows = _list(client, f"status=all&entity={HOST}")
    assert {lead["id"] for lead in rows} == set(by_name + by_address)
    assert _count(client, f"status=all&entity={HOST}") == 2


def test_a_user_named_like_the_host_stays_out(client: TestClient) -> None:
    """Negative control: an alias joins host entities only."""
    _host(client, HOST, "backup.example.test")
    _leads(client, ["user", "backup"], count=2, days_ago=1)

    assert _list(client, f"status=all&entity={HOST}") == []
    assert _count(client, f"status=all&entity={HOST}") == 0


def test_open_or_hunting_keeps_the_open_work_only(client: TestClient) -> None:
    """The hero counts open work. A closed lead is history."""
    opened = _leads(client, ["host", HOST], count=2, days_ago=4)
    hunting = _leads(client, ["host", HOST], count=1, days_ago=4, status="hunting")
    _leads(client, ["host", HOST], count=3, days_ago=4, status="dismissed")
    _leads(client, ["host", HOST], count=1, days_ago=4, status="promoted")
    _leads(client, ["host", HOST], count=1, days_ago=4, status="fleet_condition")

    rows = _list(client, f"status=open_or_hunting&entity={HOST}")
    assert {lead["id"] for lead in rows} == set(opened + hunting)
    assert _count(client, f"status=open_or_hunting&entity={HOST}") == 3
    assert _count(client, "status=open_or_hunting") == 3


def test_the_count_reads_the_same_status_rule_as_the_list(client: TestClient) -> None:
    _leads(client, ["host", HOST], count=2, days_ago=1)
    _leads(client, ["host", HOST], count=3, days_ago=1, status="dismissed")

    _leads(client, ["host", OTHER], count=4, days_ago=1)

    for status in ("open", "closed", "all", "needs_decision", "in_progress", "new"):
        assert _count(client, f"status={status}") == len(_list(client, f"status={status}"))
        # The entity path reads the same rule, joins included.
        query = f"status={status}&entity={HOST}"
        assert _count(client, query) == len(_list(client, query))
    assert _count(client, f"status=closed&entity={HOST}") == 3
    assert _count(client, f"status=new&entity={HOST}") == 2


def test_a_blank_entity_is_refused(client: TestClient) -> None:
    """A blank entity matched every lead, and a host page then listed the estate."""
    _leads(client, ["host", HOST], count=1, days_ago=1)
    for path in ("/api/v1/leads?status=all&entity=%20", "/api/v1/leads/count?status=all&entity="):
        res = client.get(path)
        assert res.status_code == 422, res.text
        assert res.json()["detail"]["reason"] == "entity_required"


def test_the_count_refuses_an_unknown_status(client: TestClient) -> None:
    res = client.get("/api/v1/leads/count?status=bogus")
    assert res.status_code == 422, res.text
    assert res.json()["detail"]["reason"] == "bad_filter"


# ---------------------------------------------------------------------------
# The dossier window
# ---------------------------------------------------------------------------


def test_the_dossier_states_its_lookback(client: TestClient) -> None:
    """The host page labels the sweep counts with the window they cover."""
    _host(client, HOST, None)
    body = client.get(f"/api/v1/dossiers/{HOST}").json()
    assert body["lookback_days"] == 14
