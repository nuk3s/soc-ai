"""The Analytic hits block of the Hunts page (production review 2026-11-12).

F3. The block read "last 7 days · 249". 39 of the 249 hits were from the last
7 days. The other hits were older unread shadow hits, which the list holds at
any age. GET /hunts/hits now states the two counts apart.

F2. 233 unread hits came from 3 analytics, and each card repeated the two
decisions on the analytic. GET /hunts/hits now sends one group for each
analytic, and POST /hunts/shadow-hits/read-analytic marks the unread hits of
one analytic.
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

from tests.test_analytics_store import SPEC_TEXT

_LOCAL = "local-svc-ticket-from-workstation"
_SHIPPED = "identity-4662-dcsync-nonmachine"
_OTHER_SHIPPED = "prior-hypervisor-novel-served-port"


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


def _ago(hours: float) -> datetime:
    """A stored time that many hours back from now. Relative, so no window rots."""
    return (datetime.now(UTC) - timedelta(hours=hours)).replace(tzinfo=None)


def _shadow_analytic(client: TestClient) -> None:
    """Put the local analytic in shadow, so its hits are shadow hits."""
    if _LOCAL not in {a["id"] for a in client.get("/api/v1/analytics").json()["analytics"]}:
        client.post("/api/v1/analytics", json={"spec_text": SPEC_TEXT})
    client.post(f"/api/v1/analytics/{_LOCAL}/status", json={"to": "shadow", "why": "seed"})


_SEQ = iter(range(1, 10_000))


def _hit(client: TestClient, **fields: Any) -> int:
    """One observation row an analytic wrote. A shadow hit of the local analytic by default."""
    from soc_ai.store.models import EntityObservation

    n = next(_SEQ)
    born = fields.pop("born_at", _ago(1))

    async def go() -> int:
        async with client.app.state.db_sessionmaker() as db:
            row = EntityObservation(
                entity_kind=fields.pop("entity_kind", "host"),
                entity_key=fields.pop("entity_key", "10.1.2.3"),
                kind="catalog_match",
                spec_id=fields.pop("spec_id", _LOCAL),
                fingerprint=fields.pop("fingerprint", f"fp-{n}"),
                birth_weight=0.7,
                born_at=born,
                first_seen_at=fields.pop("first_seen_at", born),
                occurrences=1,
                source=fields.pop("source", "catalog"),
                shadow=fields.pop("shadow", True),
                **fields,
            )
            db.add(row)
            await db.commit()
            return int(row.id)

    return asyncio.run(go())


# ---------------------------------------------------------------------------
# F3: two counts, each with its own window
# ---------------------------------------------------------------------------


def _seed_window(client: TestClient) -> dict[str, int]:
    """Hits inside the 7 day window, and older ones, read and unread."""
    _shadow_analytic(client)
    return {
        "live_new": _hit(client, spec_id=_SHIPPED, shadow=False, born_at=_ago(3)),
        "shadow_new_unread": _hit(client, born_at=_ago(5)),
        "shadow_new_read": _hit(client, born_at=_ago(30), read_at=_ago(2)),
        "shadow_old_unread_a": _hit(client, born_at=_ago(24 * 9)),
        "shadow_old_unread_b": _hit(client, born_at=_ago(24 * 40)),
        # Outside the window and read, or live: the list holds neither.
        "shadow_old_read": _hit(client, born_at=_ago(24 * 9), read_at=_ago(24 * 8)),
        "live_old": _hit(client, spec_id=_SHIPPED, shadow=False, born_at=_ago(24 * 9)),
    }


def test_the_hit_list_states_the_window_count_and_the_older_unread_count(
    client: TestClient,
) -> None:
    _seed_window(client)
    body = client.get("/api/v1/hunts/hits").json()
    assert body["window"] == {"days": 7, "in_window": 3, "older_unread": 2}
    # The list still holds every unread shadow hit at any age. The two counts
    # are the parts of the one total the All chip states.
    assert body["counts"]["all"] == 5
    assert body["window"]["in_window"] + body["window"]["older_unread"] == body["counts"]["all"]


def test_the_two_counts_follow_the_days_parameter(client: TestClient) -> None:
    """The window is the caller's. A hit 9 days old is inside 30 days."""
    _seed_window(client)
    body = client.get("/api/v1/hunts/hits?days=30").json()
    # 9 days back: one unread shadow hit, one read shadow hit and one live hit
    # join the window. The hit 40 days back stays outside it.
    assert body["window"] == {"days": 30, "in_window": 6, "older_unread": 1}
    assert body["window"]["in_window"] + body["window"]["older_unread"] == body["counts"]["all"]


def test_an_old_read_hit_and_an_old_live_hit_are_in_neither_count(client: TestClient) -> None:
    """NEGATIVE CONTROL. "Older unread" counts unread shadow hits and no other hit."""
    _shadow_analytic(client)
    _hit(client, born_at=_ago(24 * 9), read_at=_ago(24 * 8))
    _hit(client, spec_id=_SHIPPED, shadow=False, born_at=_ago(24 * 9))
    body = client.get("/api/v1/hunts/hits").json()
    assert body["window"] == {"days": 7, "in_window": 0, "older_unread": 0}
    assert body["counts"]["all"] == 0


def test_a_retired_analytic_is_in_neither_count(client: TestClient) -> None:
    """NEGATIVE CONTROL. The counts read the rule of the list, so a hidden hit is not counted."""
    _shadow_analytic(client)
    _hit(client, born_at=_ago(2))
    _hit(client, born_at=_ago(24 * 20))
    assert client.get("/api/v1/hunts/hits").json()["window"] == {
        "days": 7,
        "in_window": 1,
        "older_unread": 1,
    }
    client.post(f"/api/v1/analytics/{_LOCAL}/status", json={"to": "retired", "why": "too noisy"})
    assert client.get("/api/v1/hunts/hits").json()["window"] == {
        "days": 7,
        "in_window": 0,
        "older_unread": 0,
    }


def test_the_window_counts_do_not_follow_the_filter_or_the_page(client: TestClient) -> None:
    """The label is about the block. A chip or a page does not change it."""
    _seed_window(client)
    full = client.get("/api/v1/hunts/hits").json()["window"]
    for query in ("filter=live", "filter=unread", "filter=shadow", "limit=1", "limit=1&offset=3"):
        assert client.get(f"/api/v1/hunts/hits?{query}").json()["window"] == full, query


# ---------------------------------------------------------------------------
# F2: one group for each analytic, and one read for each group
# ---------------------------------------------------------------------------


def _machine(client: TestClient, name: str, addresses: list[str]) -> None:
    """One machine that holds these addresses, as the host sweep writes it."""
    from soc_ai.store.models import HostDossier, HostMachine

    async def go() -> None:
        async with client.app.state.db_sessionmaker() as db:
            machine = HostMachine(
                machine_key=f"agent:{name}",
                name=name,
                primary_ip=addresses[0],
                address_count=len(addresses),
            )
            db.add(machine)
            await db.flush()
            for ip in addresses:
                db.add(HostDossier(host_key=ip, ip=ip, machine_id=machine.id))
            await db.commit()

    asyncio.run(go())


def _seed_groups(client: TestClient) -> dict[str, int]:
    """Three analytics. The local one holds four shadow hits on three addresses of two machines."""
    _shadow_analytic(client)
    _machine(client, "mainsrv", ["10.1.2.3", "172.17.0.1"])
    return {
        "a": _hit(client, entity_key="10.1.2.3", born_at=_ago(2)),
        "b": _hit(client, entity_key="172.17.0.1", born_at=_ago(3)),
        "c": _hit(client, entity_key="10.9.9.9", born_at=_ago(24 * 20)),
        "d": _hit(client, entity_key="10.9.9.9", born_at=_ago(4), read_at=_ago(1)),
        "live": _hit(
            client, spec_id=_SHIPPED, shadow=False, born_at=_ago(1), entity_key="10.1.2.3"
        ),
        "user": _hit(
            client,
            spec_id=_OTHER_SHIPPED,
            shadow=False,
            born_at=_ago(6),
            entity_kind="user",
            entity_key="jdoe",
        ),
    }


def _groups(client: TestClient, query: str = "") -> dict[str, dict[str, Any]]:
    body = client.get(f"/api/v1/hunts/hits{query}").json()
    return {g["analytic_id"]: g for g in body["groups"]}


def test_the_hit_list_sends_one_group_for_each_analytic(client: TestClient) -> None:
    _seed_groups(client)
    groups = _groups(client)
    assert set(groups) == {_LOCAL, _SHIPPED, _OTHER_SHIPPED}
    local = groups[_LOCAL]
    assert local["hits"] == 4
    assert local["unread"] == 3
    assert local["analytic_status"] == "shadow"
    assert local["tier"] == "local"
    assert local["analytic_exists"] is True
    # Three addresses. Two of them are one machine.
    assert local["machines"] == 2
    assert local["accounts"] == 0
    live = groups[_SHIPPED]
    assert (live["hits"], live["unread"], live["machines"]) == (1, 0, 1)
    assert live["analytic_status"] == "live"
    # A hit on an account names no machine.
    assert (groups[_OTHER_SHIPPED]["machines"], groups[_OTHER_SHIPPED]["accounts"]) == (0, 1)


def test_the_groups_count_the_whole_list_and_not_the_page(client: TestClient) -> None:
    """A page of one row still states four hits for the analytic."""
    _seed_groups(client)
    page = client.get("/api/v1/hunts/hits?limit=1").json()
    assert len(page["hits"]) == 1
    groups = {g["analytic_id"]: g for g in page["groups"]}
    assert groups[_LOCAL]["hits"] == 4
    assert sum(g["hits"] for g in page["groups"]) == page["counts"]["all"]
    assert sum(g["unread"] for g in page["groups"]) == page["counts"]["unread"]


def test_the_groups_follow_the_filter(client: TestClient) -> None:
    _seed_groups(client)
    unread = _groups(client, "?filter=unread")
    assert set(unread) == {_LOCAL}
    assert (unread[_LOCAL]["hits"], unread[_LOCAL]["unread"]) == (3, 3)
    live = _groups(client, "?filter=live")
    assert set(live) == {_SHIPPED, _OTHER_SHIPPED}


def test_the_group_with_unread_hits_comes_first(client: TestClient) -> None:
    """Needs-you counts the unread hits, so their analytic leads the block."""
    _seed_groups(client)
    order = [g["analytic_id"] for g in client.get("/api/v1/hunts/hits").json()["groups"]]
    assert order[0] == _LOCAL
    # Then newest first: the live hit of 1 hour back, then the one of 6 hours.
    assert order[1:] == [_SHIPPED, _OTHER_SHIPPED]


def _read_analytic(client: TestClient, analytic_id: str, **body: Any) -> Any:
    payload = {"analytic_id": analytic_id, "before": datetime.now(UTC).isoformat(), **body}
    return client.post("/api/v1/hunts/shadow-hits/read-analytic", json=payload)


def test_one_press_marks_the_unread_hits_of_one_analytic(client: TestClient) -> None:
    ids = _seed_groups(client)
    assert client.get("/api/v1/hunts/needs-you").json()["unread_shadow_hits"] == 3
    res = _read_analytic(client, _LOCAL, expected=3)
    assert res.status_code == 200, res.text
    assert res.json() == {"read": 3}
    assert client.get("/api/v1/hunts/needs-you").json()["unread_shadow_hits"] == 0
    by_id = {h["id"]: h for h in client.get("/api/v1/hunts/hits?days=30").json()["hits"]}
    assert all(by_id[ids[k]]["read"] is True for k in ("a", "b", "c", "d"))
    # A second press reads nothing and is no error.
    assert _read_analytic(client, _LOCAL).json() == {"read": 0}


def test_the_read_of_one_analytic_leaves_every_other_hit_unread(client: TestClient) -> None:
    """NEGATIVE CONTROL. The scope is one analytic."""
    from soc_ai.store.models import EntityObservation

    _shadow_analytic(client)
    mine = _hit(client)
    # A shadow hit of a second analytic. The catalog does not list it, so the
    # row flag is its status, and it stays an unread shadow hit.
    other = _hit(client, spec_id="local-another-analytic")
    assert _read_analytic(client, _LOCAL).json() == {"read": 1}

    async def read_at(obs_id: int) -> Any:
        async with client.app.state.db_sessionmaker() as db:
            row = await db.get(EntityObservation, obs_id)
            assert row is not None
            return row.read_at

    assert asyncio.run(read_at(mine)) is not None
    assert asyncio.run(read_at(other)) is None
    assert client.get("/api/v1/hunts/needs-you").json()["unread_shadow_hits"] == 1


def test_the_read_of_one_analytic_leaves_a_hit_born_after_the_mark(client: TestClient) -> None:
    """NEGATIVE CONTROL. A hit the analyst was not shown stays unread."""
    _shadow_analytic(client)
    _hit(client, born_at=_ago(5))
    mark = _ago(2).replace(tzinfo=UTC).isoformat()
    _hit(client, born_at=_ago(1))
    res = client.post(
        "/api/v1/hunts/shadow-hits/read-analytic", json={"analytic_id": _LOCAL, "before": mark}
    )
    assert res.json() == {"read": 1}
    assert client.get("/api/v1/hunts/needs-you").json()["unread_shadow_hits"] == 1


def test_the_read_of_one_analytic_refuses_more_hits_than_the_button_stated(
    client: TestClient,
) -> None:
    """NEGATIVE CONTROL. The button stated 1. Two hits are unread, so nothing is marked."""
    _shadow_analytic(client)
    _hit(client)
    _hit(client)
    res = _read_analytic(client, _LOCAL, expected=1)
    assert res.status_code == 409
    assert res.json()["detail"]["reason"] == "shadow_hits_changed"
    assert client.get("/api/v1/hunts/needs-you").json()["unread_shadow_hits"] == 2


def test_the_read_of_one_analytic_needs_an_analytic_and_a_mark(client: TestClient) -> None:
    res = client.post(
        "/api/v1/hunts/shadow-hits/read-analytic",
        json={"analytic_id": "  ", "before": datetime.now(UTC).isoformat()},
    )
    assert res.status_code == 422
    assert res.json()["detail"]["reason"] == "analytic_required"
    res = client.post(
        "/api/v1/hunts/shadow-hits/read-analytic", json={"analytic_id": _LOCAL, "before": "soon"}
    )
    assert res.status_code == 422
    assert res.json()["detail"]["reason"] == "bad_before"


def test_the_read_of_one_analytic_writes_one_audit_record(client: TestClient) -> None:
    _shadow_analytic(client)
    _hit(client)
    audit = AsyncMock()
    client.app.state.audit = audit  # type: ignore[attr-defined]
    assert _read_analytic(client, _LOCAL).json() == {"read": 1}
    assert audit.log_kind.await_count == 1
    args = audit.log_kind.await_args.args
    assert args[1] == "shadow_hits_read"
    assert args[2]["read"] == 1
    assert args[2]["analytic_id"] == _LOCAL
