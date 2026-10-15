"""The bell list pages, dates its rows, and Dismiss all reads every shadow hit.

Production 2026-10-14: the bell badge read 309 and the panel it opened listed
12 rows, all shadow hits. The badge is the needs-you count, and the list was
cut at 12 rows with per-source caps under that. The analyst could not see what
the number counted, and could not clear 300 shadow hits from the bell.

* ``GET /notifications`` takes a ``limit``. The default stays 12, so an older
  console sees no change. The per-source caps grow with the limit, so a larger
  limit returns more rows. ``events_only`` leaves out the needs-you rows, which
  the console shows as counts.
* Every row with a time carries ``at``, so the console can hide the rows up to
  the moment of a Dismiss all.
* ``POST /hunts/shadow-hits/read-all`` marks every unread shadow hit born up to
  a mark as read, in one write, and records the act in the audit trail.
"""

from __future__ import annotations

import asyncio
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta, timezone
from typing import Any
from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient
from soc_ai.config import Settings
from soc_ai.main import create_app

from tests.test_analytics_api import _RETIRABLE, _insert_observation, _shadow_analytic
from tests.test_needs_you_count import _seed_lead, _seed_run


@pytest.fixture
def client(settings_kratos: Settings) -> Iterator[TestClient]:
    fake_es = AsyncMock()
    fake_auth = AsyncMock()
    with (
        patch("soc_ai.so_client.elastic.AsyncElasticsearch", return_value=fake_es),
        patch("soc_ai.main.make_auth", return_value=fake_auth),
        patch("soc_ai.main.get_settings", return_value=settings_kratos),
    ):
        app = create_app()
        with TestClient(app) as test_client:
            yield test_client


def _ago(hours: float) -> datetime:
    """A stored (naive UTC) timestamp that many hours back from now."""
    return (datetime.now(UTC) - timedelta(hours=hours)).replace(tzinfo=None)


def _notifications(client: TestClient, **params: Any) -> list[dict[str, Any]]:
    res = client.get("/api/v1/notifications", params=params)
    assert res.status_code == 200, res.text
    body: list[dict[str, Any]] = res.json()
    return body


def _prefix(row: dict[str, Any]) -> str:
    return str(row["id"]).split(":", 1)[0]


def _seed_completed_runs(client: TestClient, n: int) -> None:
    for i in range(n):
        _seed_run(
            client,
            f"INV-DONE-{i:03d}",
            alert_id=f"es-done-{i}",
            verdict="false_positive",
            hours_ago=1 + i / 100,
        )


def _seed_unread_hits(client: TestClient, n: int, *, hours_ago: float = 2.0) -> list[int]:
    _shadow_analytic(client)
    return [
        _insert_observation(
            client,
            fingerprint=f"fp-hit-{i}",
            source="catalog",
            shadow=True,
            born_at=_ago(hours_ago + i / 100),
        )
        for i in range(n)
    ]


def _read_at(client: TestClient, obs_id: int) -> datetime | None:
    from soc_ai.store.models import EntityObservation

    async def go() -> datetime | None:
        async with client.app.state.db_sessionmaker() as db:
            row = await db.get(EntityObservation, obs_id)
            assert row is not None
            return row.read_at

    return asyncio.run(go())


# ---------------------------------------------------------------------------
# The limit
# ---------------------------------------------------------------------------


def test_the_default_limit_stays_twelve(client: TestClient) -> None:
    """An older console sends no limit. It must see the list it always saw."""
    _seed_completed_runs(client, 25)
    assert len(_notifications(client)) == 12


def test_a_larger_limit_returns_more_rows_than_the_old_caps(client: TestClient) -> None:
    """The completed runs and the shadow hits were capped at 20 each. A limit
    above the cap returned 20 rows of each, so "Show more" could not show more."""
    _seed_completed_runs(client, 30)
    _seed_unread_hits(client, 25)
    rows = _notifications(client, limit=200)
    prefixes = [_prefix(r) for r in rows]
    assert prefixes.count("inv-done") == 30
    assert prefixes.count("shadow-hit") == 25
    # The limit still cuts the list.
    assert len(_notifications(client, limit=32)) == 32


def test_the_lead_rows_grow_with_the_limit(client: TestClient) -> None:
    for i in range(9):
        _seed_lead(client, formed_hours_ago=1 + i, idx=i)
    small = _notifications(client)
    assert [_prefix(r) for r in small].count("lead") == 5
    more = next(r for r in small if r["id"] == "lead-more")
    assert more["title"].startswith("4 more leads are open")

    big = _notifications(client, limit=32)
    assert [_prefix(r) for r in big].count("lead") == 9
    assert all(r["id"] != "lead-more" for r in big)


@pytest.mark.parametrize("limit", [0, -1, 201])
def test_a_limit_out_of_bounds_is_refused(client: TestClient, limit: int) -> None:
    res = client.get("/api/v1/notifications", params={"limit": limit})
    assert res.status_code == 422
    assert "limit" in res.json()["detail"]["hint"]


def test_the_largest_limit_is_two_hundred(client: TestClient) -> None:
    _seed_completed_runs(client, 3)
    assert client.get("/api/v1/notifications", params={"limit": 200}).status_code == 200


def test_events_only_leaves_out_the_rows_the_needs_you_count_holds(client: TestClient) -> None:
    """The console shows the leads and the shadow hits as counts. With 300
    unread hits, the first 12 rows of the list were all shadow hits, and the
    events behind them never reached the panel."""
    _seed_unread_hits(client, 15)
    for i in range(7):
        _seed_lead(client, formed_hours_ago=1 + i, idx=i)
    _seed_completed_runs(client, 2)

    everything = {_prefix(r) for r in _notifications(client, limit=200)}
    assert {"shadow-hit", "lead", "inv-done"} <= everything
    # The defect: at the default limit the hits fill the list.
    assert {_prefix(r) for r in _notifications(client)} == {"shadow-hit"}

    events = _notifications(client, events_only=True)
    assert [_prefix(r) for r in events] == ["inv-done", "inv-done"]


# ---------------------------------------------------------------------------
# The time of each row
# ---------------------------------------------------------------------------


def test_every_row_with_a_time_carries_it(client: TestClient) -> None:
    from soc_ai.store import hunts as hunts_svc
    from soc_ai.store.models import Investigation

    _seed_run(client, "INV-AT", alert_id="es-at", verdict="false_positive", hours_ago=3)
    hit = _seed_unread_hits(client, 1, hours_ago=5)[0]
    for i in range(6):
        _seed_lead(client, formed_hours_ago=1 + i, idx=i)

    async def seed() -> str:
        async with client.app.state.db_sessionmaker() as db:
            db.add(
                Investigation(
                    id="INV-RUNNING",
                    alert_es_id="es-running",
                    kind="suricata",
                    rule_name="ET TEST running",
                    status="running",
                    created_at=_ago(0.5),
                )
            )
            await db.commit()
            hunt = await hunts_svc.create(db, objective="find beacons", started_by="t")
            await hunts_svc.finalize(db, hunt.id, status="complete", report={"findings": []})
            return hunt.id

    hunt_id = asyncio.run(seed())
    rows = {r["id"]: r for r in _notifications(client, limit=50)}

    for row_id, row in rows.items():
        if row_id == "lead-more":
            # A count of more leads describes no moment.
            assert row["at"] is None
            continue
        assert row["at"], row_id
        stamp = datetime.fromisoformat(row["at"])
        assert stamp.tzinfo is not None, row_id

    done = datetime.fromisoformat(rows["inv-done:INV-AT"]["at"])
    assert abs((done.replace(tzinfo=None) - _ago(3)).total_seconds()) < 60
    born = datetime.fromisoformat(rows[f"shadow-hit:{hit}"]["at"])
    assert abs((born.replace(tzinfo=None) - _ago(5)).total_seconds()) < 60
    assert "inv:INV-RUNNING" in rows
    assert f"hunt-done:{hunt_id}" in rows
    assert sum(1 for r in rows if r.startswith("lead:")) == 6


# ---------------------------------------------------------------------------
# Read every shadow hit
# ---------------------------------------------------------------------------


def _read_all(client: TestClient, before: Any) -> Any:
    return client.post("/api/v1/hunts/shadow-hits/read-all", json={"before": before})


def test_read_all_marks_every_unread_hit_born_up_to_the_mark(client: TestClient) -> None:
    old = _seed_unread_hits(client, 3, hours_ago=2)
    # NEGATIVE CONTROL: born after the mark. The analyst never saw it counted.
    fresh = _insert_observation(
        client,
        fingerprint="fp-fresh",
        source="catalog",
        shadow=True,
        born_at=_ago(0.1),
    )
    # NEGATIVE CONTROL: a hit of a retired analytic is not an unread shadow hit.
    retired = _insert_observation(
        client,
        spec_id=_RETIRABLE,
        fingerprint="fp-retired",
        source="catalog",
        shadow=True,
        born_at=_ago(3),
    )
    res = client.post(
        f"/api/v1/analytics/{_RETIRABLE}/status", json={"to": "retired", "why": "no hypervisor"}
    )
    assert res.status_code == 200, res.text
    # NEGATIVE CONTROL: a hit read earlier keeps its own read time.
    earlier = _ago(10)
    read_before = _insert_observation(
        client,
        fingerprint="fp-read",
        source="catalog",
        shadow=True,
        born_at=_ago(12),
        read_at=earlier,
    )
    assert client.get("/api/v1/hunts/needs-you").json()["unread_shadow_hits"] == 4

    mark = (datetime.now(UTC) - timedelta(minutes=30)).isoformat()
    res = _read_all(client, mark)
    assert res.status_code == 200, res.text
    assert res.json() == {"read": 3}

    for obs_id in old:
        assert _read_at(client, obs_id) is not None
    assert _read_at(client, fresh) is None
    assert _read_at(client, retired) is None
    assert _read_at(client, read_before) == earlier
    assert client.get("/api/v1/hunts/needs-you").json()["unread_shadow_hits"] == 1


def test_read_all_refuses_more_hits_than_the_analyst_was_shown(client: TestClient) -> None:
    """A sweep stamps ``born_at`` before it commits. A hit born before the mark
    can land after the count was read. The analyst confirmed "mark 2 read", so
    the route must not mark 3: it marks nothing and answers 409."""
    hits = _seed_unread_hits(client, 3, hours_ago=2)
    mark = (datetime.now(UTC) - timedelta(minutes=30)).isoformat()
    res = client.post("/api/v1/hunts/shadow-hits/read-all", json={"before": mark, "expected": 2})
    assert res.status_code == 409, res.text
    assert res.json()["detail"]["reason"] == "shadow_hits_changed"
    for obs_id in hits:
        assert _read_at(client, obs_id) is None


def test_read_all_marks_the_hits_when_the_count_holds(client: TestClient) -> None:
    """NEGATIVE CONTROL. The count the analyst saw, or fewer, goes through."""
    hits = _seed_unread_hits(client, 3, hours_ago=2)
    mark = (datetime.now(UTC) - timedelta(minutes=30)).isoformat()
    res = client.post("/api/v1/hunts/shadow-hits/read-all", json={"before": mark, "expected": 3})
    assert res.status_code == 200, res.text
    assert res.json() == {"read": 3}
    for obs_id in hits:
        assert _read_at(client, obs_id) is not None


def test_read_all_takes_a_mark_with_a_zone_or_without_one(client: TestClient) -> None:
    """The store holds naive UTC. A mark in another zone is converted, and a
    mark with no zone is read as UTC."""
    _shadow_analytic(client)
    hit = _insert_observation(
        client, fingerprint="fp-zone", source="catalog", shadow=True, born_at=_ago(2)
    )
    # One hour ago, written at -05:00. With the zone dropped and not converted,
    # the wall time reads six hours ago and misses the hit born two hours ago.
    west = (datetime.now(UTC) - timedelta(hours=1)).astimezone(timezone(timedelta(hours=-5)))
    assert _read_all(client, west.isoformat()).json() == {"read": 1}
    assert _read_at(client, hit) is not None

    other = _insert_observation(
        client, fingerprint="fp-naive", source="catalog", shadow=True, born_at=_ago(2)
    )
    naive = (datetime.now(UTC) - timedelta(hours=1)).replace(tzinfo=None).isoformat()
    assert _read_all(client, naive).json() == {"read": 1}
    assert _read_at(client, other) is not None
    # A Z suffix is the form the browser writes.
    assert _read_all(client, "2020-01-01T00:00:00Z").json() == {"read": 0}


@pytest.mark.parametrize("body", [{}, {"before": ""}, {"before": "yesterday"}, {"before": None}])
def test_read_all_refuses_a_missing_or_bad_mark(client: TestClient, body: dict[str, Any]) -> None:
    hits = _seed_unread_hits(client, 2)
    res = client.post("/api/v1/hunts/shadow-hits/read-all", json=body)
    assert res.status_code == 422
    assert res.json()["detail"]["reason"] in ("bad_request", "bad_before")
    # A refused request reads nothing.
    for obs_id in hits:
        assert _read_at(client, obs_id) is None


def test_read_all_writes_one_audit_record(client: TestClient) -> None:
    _seed_unread_hits(client, 2)
    audit = AsyncMock()
    client.app.state.audit = audit  # type: ignore[attr-defined]
    mark = datetime.now(UTC).isoformat()
    assert _read_all(client, mark).json() == {"read": 2}

    assert audit.log_kind.await_count == 1
    call = audit.log_kind.await_args
    assert call.args[1] == "shadow_hits_read"
    payload = call.args[2]
    assert payload["read"] == 2
    assert payload["before"].startswith(mark[:19])
    assert call.kwargs["user"] == "anonymous"


def test_a_failed_audit_write_keeps_the_read(client: TestClient) -> None:
    """The read is committed first. Losing it to an audit outage is worse than
    losing the audit line, the rule the dossier writes follow."""
    hits = _seed_unread_hits(client, 1)
    audit = AsyncMock()
    audit.log_kind.side_effect = RuntimeError("audit index down")
    client.app.state.audit = audit  # type: ignore[attr-defined]
    assert _read_all(client, datetime.now(UTC).isoformat()).json() == {"read": 1}
    assert _read_at(client, hits[0]) is not None


def test_the_audit_kind_is_declared() -> None:
    """An undeclared kind fails validation inside the logger and the record is
    dropped, the trap the AuditKind comments describe."""
    from soc_ai.audit.schemas import AuditEvent

    event = AuditEvent(session_id="shadow-hits", kind="shadow_hits_read", payload={"read": 1})
    assert event.kind == "shadow_hits_read"


def test_the_bell_drops_a_read_hit(client: TestClient) -> None:
    hits = _seed_unread_hits(client, 2)
    before = {r["id"] for r in _notifications(client)}
    assert {f"shadow-hit:{h}" for h in hits} <= before
    _read_all(client, datetime.now(UTC).isoformat())
    after = {r["id"] for r in _notifications(client)}
    assert not any(row_id.startswith("shadow-hit:") for row_id in after)


# ---------------------------------------------------------------------------
# The rows after a Dismiss all
# ---------------------------------------------------------------------------


def test_after_drops_the_dismissible_rows_up_to_the_mark(client: TestClient) -> None:
    """The console sends its Dismiss all mark. The rows up to it take no place
    in the limit, so the list holds the rows the analyst has not seen. Without
    it, the hidden rows filled the list and "Show more" offered nothing."""
    from types import SimpleNamespace

    for i in range(15):
        _seed_run(
            client,
            f"INV-OLD-{i:02d}",
            alert_id=f"es-old-{i}",
            verdict="false_positive",
            hours_ago=3 + i / 10,
        )
    for i in range(3):
        _seed_run(
            client,
            f"INV-NEW-{i}",
            alert_id=f"es-new-{i}",
            verdict="false_positive",
            hours_ago=0.5 + i / 10,
        )
    for i in range(6):
        _seed_lead(client, formed_hours_ago=4 + i, idx=i)
    # NEGATIVE CONTROL: a tamper finding the server marks undismissible. It is
    # older than the mark and stays.
    old = (datetime.now(UTC) - timedelta(hours=10)).isoformat()
    client.app.state._audit_verify_status = SimpleNamespace(  # type: ignore[attr-defined]
        alarm={
            "detected_at": old,
            "alarm_since": old,
            "alarm_key": "content_altered|x|1",
            "break_kind": "content_altered",
            "dismissible": False,
        }
    )
    mark = (datetime.now(UTC) - timedelta(hours=2)).isoformat()

    ids = [r["id"] for r in _notifications(client, after=mark)]
    assert [i for i in ids if i.startswith("inv-done:")] == [
        "inv-done:INV-NEW-0",
        "inv-done:INV-NEW-1",
        "inv-done:INV-NEW-2",
    ]
    assert any(i.startswith("audit-chain-break:") for i in ids)
    # The count of more leads describes no moment, and it is not dismissible.
    assert "lead-more" in ids
    assert not any(i.startswith("lead:") for i in ids)

    # Without the mark the old runs fill the list as before.
    assert sum(1 for r in _notifications(client) if r["id"].startswith("inv-done:")) > 3


def test_a_bad_after_is_refused(client: TestClient) -> None:
    res = client.get("/api/v1/notifications", params={"after": "last week"})
    assert res.status_code == 422
    assert res.json()["detail"]["reason"] == "bad_after"
