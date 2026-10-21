"""The routes and the CLI of the grid-gap recovery.

An operator records a gap that soc-ai did not see, reviews the hits the gap
wrote, marks them benign in one write, and reads which holds the gap caused
(dogfood 2026-10-19, R1-I5, R3-I1, R3-I2, R4-I3). Every row is seeded relative
to now.
"""

from __future__ import annotations

import asyncio
import itertools
import sys
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient
from soc_ai.config import Settings
from soc_ai.hunting import self_heal
from soc_ai.main import create_app
from soc_ai.store import analytics as analytics_store
from soc_ai.store import grid_gaps
from soc_ai.store.db import make_engine, make_sessionmaker, run_migrations
from soc_ai.store.models import EntityObservation, GridGap, Lead
from sqlalchemy import select

from tests.test_analytics_store import SPEC_TEXT

_ID = "local-svc-ticket-from-workstation"
_ORIGIN = {"Origin": "http://testserver"}
_seq = itertools.count(1)


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


def _now() -> datetime:
    return datetime.now(UTC).replace(tzinfo=None, microsecond=0)


def _z(at: datetime) -> str:
    return at.replace(tzinfo=UTC).isoformat().replace("+00:00", "Z")


def _run(client: TestClient, fn: Any) -> Any:
    async def go() -> Any:
        async with client.app.state.db_sessionmaker() as db:  # type: ignore[attr-defined]
            return await fn(db)

    return asyncio.run(go())


def _hit(
    *,
    host: str,
    born: datetime,
    start: datetime,
    end: datetime,
    spec_id: str = "profile-connection-rate-collapsed",
    lead_id: int | None = None,
) -> EntityObservation:
    return EntityObservation(
        entity_kind="host",
        entity_key=host,
        kind="below_baseline",
        spec_id=spec_id,
        fingerprint=f"fp-{next(_seq)}",
        birth_weight=0.5,
        born_at=born,
        first_seen_at=born,
        occurrences=1,
        source="profile",
        shadow=False,
        evidence_json={"window": {"start": _z(start), "end": _z(end)}},
        lead_id=lead_id,
    )


def _post_gap(client: TestClient, now: datetime, **over: Any) -> Any:
    body = {
        "started_at": _z(now - timedelta(days=4)),
        "ended_at": _z(now - timedelta(hours=3)),
        "detail": "The sensor VM was down.",
    }
    body.update(over)
    return client.post("/api/v1/grid/gaps", json=body, headers=_ORIGIN)


# ── POST /grid/gaps ──────────────────────────────────────────────────────────


def test_an_operator_records_a_gap_and_the_route_audits_it(client: TestClient) -> None:
    now = _now()
    audit = AsyncMock()
    client.app.state.audit = audit  # type: ignore[attr-defined]
    res = _post_gap(client, now)
    assert res.status_code == 201, res.text
    gap = res.json()
    assert gap["source"] == "operator"
    assert gap["open"] is False
    assert gap["started_at"] == _z(now - timedelta(days=4))
    assert gap["detail"] == "The sensor VM was down."
    # The same gap again: no second row, and the answer names the first one.
    again = _post_gap(client, now)
    assert again.status_code == 200
    assert again.json()["id"] == gap["id"]
    listed = client.get("/api/v1/grid/gaps").json()["gaps"]
    assert [g["id"] for g in listed] == [gap["id"]]

    kinds = [call.args[1] for call in audit.log_kind.await_args_list]
    assert kinds == ["grid_gap_recorded", "grid_gap_recorded"]
    payload = audit.log_kind.await_args_list[0].args[2]
    assert payload["gap_id"] == gap["id"]
    assert payload["created"] is True
    assert payload["started_at"] == gap["started_at"]


@pytest.mark.parametrize(
    ("start", "end", "code"),
    [
        (timedelta(hours=-3), timedelta(hours=-4), "gap_end_before_start"),
        (timedelta(days=-40), timedelta(days=-9), "gap_too_long"),
        (timedelta(hours=1), timedelta(hours=2), "gap_start_in_future"),
        (timedelta(hours=-1), timedelta(hours=3), "gap_end_in_future"),
    ],
)
def test_the_route_refuses_a_bad_gap(
    client: TestClient, start: timedelta, end: timedelta, code: str
) -> None:
    now = _now()
    res = _post_gap(client, now, started_at=_z(now + start), ended_at=_z(now + end))
    assert res.status_code == 422
    assert res.json()["detail"]["reason"] == code
    assert client.get("/api/v1/grid/gaps").json()["gaps"] == []


def test_the_route_refuses_a_time_it_cannot_read(client: TestClient) -> None:
    res = _post_gap(client, _now(), started_at="yesterday")
    assert res.status_code == 400
    assert res.json()["detail"]["reason"] == "bad_time"


def test_only_an_admin_records_a_gap(analyst: TestClient, admin: TestClient) -> None:
    now = _now()
    assert _post_gap(analyst, now).status_code == 403
    assert _post_gap(admin, now).status_code == 201


# ── review and mark ──────────────────────────────────────────────────────────


def _seed_gap_hits(client: TestClient, now: datetime) -> dict[str, Any]:
    sweep = now - timedelta(minutes=150)

    async def go(db: Any) -> dict[str, Any]:
        lead = Lead(
            status="open",
            entities_json=[["host", "192.0.2.10"]],
            kinds_json=["below_baseline"],
            weight_at_formation=1.0,
        )
        db.add(lead)
        await db.flush()
        inside = _hit(
            host="192.0.2.10",
            born=sweep,
            start=now - timedelta(hours=27),
            end=now - timedelta(hours=4),
            lead_id=lead.id,
        )
        second = _hit(
            host="192.0.2.11",
            born=sweep,
            start=now - timedelta(hours=20),
            end=now - timedelta(hours=4),
        )
        # The negative control: another host, the same sweep, a run before the gap.
        before = _hit(
            host="192.0.2.20",
            born=sweep,
            start=now - timedelta(days=6),
            end=now - timedelta(days=5),
        )
        db.add_all([inside, second, before])
        await db.commit()
        row, _ = await grid_gaps.record_operator_gap(
            db,
            started_at=now - timedelta(days=4),
            ended_at=now - timedelta(hours=3),
            detail="",
            now=now,
        )
        return {
            "gap": int(row.id),
            "lead": int(lead.id),
            "inside": int(inside.id),
            "second": int(second.id),
            "before": int(before.id),
        }

    seeded: dict[str, Any] = _run(client, go)
    return seeded


def test_the_recorded_gap_states_the_hits_it_holds(client: TestClient) -> None:
    """The answer to the record names the hits to review, as the ledger does."""
    now = _now()

    async def go(db: Any) -> None:
        db.add(
            _hit(
                host="192.0.2.10",
                born=now - timedelta(minutes=150),
                start=now - timedelta(hours=27),
                end=now - timedelta(hours=4),
            )
        )
        await db.commit()

    _run(client, go)
    res = _post_gap(client, now)
    assert res.status_code == 201
    assert res.json()["hits_to_review"] == 1


def test_the_ledger_counts_the_hits_to_review_on_each_gap(client: TestClient) -> None:
    ids = _seed_gap_hits(client, _now())
    (gap,) = client.get("/api/v1/grid/gaps").json()["gaps"]
    assert gap["id"] == ids["gap"]
    assert gap["hits_to_review"] == 2


def test_the_review_lists_the_hits_and_the_mark_writes_one_reason(client: TestClient) -> None:
    now = _now()
    ids = _seed_gap_hits(client, now)
    review = client.get(f"/api/v1/grid/gaps/{ids['gap']}/hits")
    assert review.status_code == 200, review.text
    body = review.json()
    assert body["count"] == 2
    assert sorted(h["id"] for h in body["hits"]) == sorted([ids["inside"], ids["second"]])
    assert body["leads"] == [ids["lead"]]
    assert body["note"].startswith("Grid gap from ")
    assert body["settle_minutes"] == 60
    assert body["review_end"] == _z(now - timedelta(hours=2))
    first = next(h for h in body["hits"] if h["id"] == ids["inside"])
    assert first["entity_key"] == "192.0.2.10"
    assert first["event_start"] == _z(now - timedelta(hours=27))
    assert first["lead_id"] == ids["lead"]

    # Both hits lie inside the gap: the review selects both.
    assert all(h["selected_by_default"] and h["inside_gap"] for h in body["hits"])
    assert all(h["reasons"] == [] for h in body["hits"])
    assert body["selected_count"] == 2

    audit = AsyncMock()
    client.app.state.audit = audit  # type: ignore[attr-defined]
    url = f"/api/v1/grid/gaps/{ids['gap']}/hits/benign"
    # The route marks only named hits. The old body with no ids marked every
    # listed hit, and a real spike with them (G-1).
    bare = client.post(url, json={"expected": 2}, headers=_ORIGIN)
    assert bare.status_code == 422
    assert bare.json()["detail"]["reason"] == "gap_ids_required"
    empty = client.post(url, json={"ids": [], "expected": 0}, headers=_ORIGIN)
    assert empty.status_code == 422
    assert empty.json()["detail"]["reason"] == "gap_ids_required"
    # ``expected`` guards the selected set.
    picked = [ids["inside"], ids["second"]]
    mismatch = client.post(url, json={"ids": picked, "expected": 1}, headers=_ORIGIN)
    assert mismatch.status_code == 422
    assert mismatch.json()["detail"]["reason"] == "gap_selection_mismatch"
    # A selected id that is not in the gap list writes nothing.
    stale = client.post(url, json={"ids": [*picked, ids["before"]], "expected": 3}, headers=_ORIGIN)
    assert stale.status_code == 409
    assert stale.json()["detail"]["reason"] == "gap_hits_changed"
    assert stale.json()["detail"]["hint"] == (
        "1 of the selected hits is no longer in the gap list. "
        "Open the review again and select the hits again."
    )
    assert client.get(f"/api/v1/grid/gaps/{ids['gap']}/hits").json()["count"] == 2
    assert audit.log_kind.await_args_list == []
    marked = client.post(url, json={"ids": picked, "expected": 2}, headers=_ORIGIN)
    assert marked.status_code == 200, marked.text
    result = marked.json()
    assert result["marked"] == 2
    assert result["leads"] == [ids["lead"]]
    assert [call.args[1] for call in audit.log_kind.await_args_list] == ["grid_gap_hits_benign"]

    hits = {h["id"]: h for h in client.get("/api/v1/hunts/hits?filter=live").json()["hits"]}
    assert hits[ids["inside"]]["dismissed_reason"] == "grid_gap"
    assert hits[ids["inside"]]["dismissed_note"] == body["note"]
    assert hits[ids["before"]]["dismissed_reason"] is None
    # The review is empty now, and the strip has nothing left to offer.
    assert client.get(f"/api/v1/grid/gaps/{ids['gap']}/hits").json()["count"] == 0
    assert client.get("/api/v1/grid/gaps").json()["gaps"][0]["hits_to_review"] == 0

    # The hit keeps its lead. The lead reads its weight from what remains.
    lead = client.get(f"/api/v1/hunts/leads/{ids['lead']}").json()
    assert lead["status"] == "open"
    row = next(o for o in lead["observations"] if o["id"] == ids["inside"])
    assert row["dismissed_reason"] == "grid_gap"
    assert row["weight_now"] == 0
    assert lead["weight_now"] == 0


def test_the_review_selects_the_inside_hits_and_marks_only_the_selection(
    client: TestClient,
) -> None:
    """The range review of gap 2 listed spikes and edge hits beside the outage (G-1)."""
    now = _now()
    gap_start = now - timedelta(days=4)

    async def go(db: Any) -> dict[str, int]:
        inside = _hit(
            host="192.0.2.11",
            born=now - timedelta(minutes=150),
            start=now - timedelta(hours=24),
            end=now - timedelta(hours=3),
        )
        spike = _hit(
            host="198.51.100.254",
            born=gap_start + timedelta(hours=3),
            start=gap_start + timedelta(hours=1),
            end=gap_start + timedelta(hours=2),
            spec_id="profile-connection-rate-spiked",
        )
        spike.kind = "above_baseline"
        runs_on = _hit(
            host="203.0.113.123",
            born=now - timedelta(minutes=50),
            start=now - timedelta(hours=21),
            end=now - timedelta(hours=1),
        )
        db.add_all([inside, spike, runs_on])
        await db.commit()
        row, _ = await grid_gaps.record_operator_gap(
            db, started_at=gap_start, ended_at=now - timedelta(hours=3), detail="", now=now
        )
        return {
            "gap": int(row.id),
            "inside": int(inside.id),
            "spike": int(spike.id),
            "runs_on": int(runs_on.id),
        }

    ids: dict[str, int] = _run(client, go)
    body = client.get(f"/api/v1/grid/gaps/{ids['gap']}/hits").json()
    assert body["count"] == 3
    assert body["selected_count"] == 1
    hits = {h["id"]: h for h in body["hits"]}
    assert hits[ids["inside"]]["selected_by_default"] is True
    assert hits[ids["spike"]]["selected_by_default"] is False
    assert hits[ids["spike"]]["inside_gap"] is True
    assert hits[ids["spike"]]["reasons"] == [
        "A gap does not explain a spike. Check for a back-fill burst."
    ]
    assert hits[ids["runs_on"]]["inside_gap"] is False
    assert hits[ids["runs_on"]]["reasons"] == ["Part of this window is outside the gap."]

    marked = client.post(
        f"/api/v1/grid/gaps/{ids['gap']}/hits/benign",
        json={"ids": [ids["inside"]], "expected": 1},
        headers=_ORIGIN,
    )
    assert marked.status_code == 200, marked.text
    assert marked.json()["ids"] == [ids["inside"]]
    left = client.get(f"/api/v1/grid/gaps/{ids['gap']}/hits").json()
    assert sorted(h["id"] for h in left["hits"]) == sorted([ids["spike"], ids["runs_on"]])
    assert left["selected_count"] == 0


def test_the_review_refuses_an_unknown_gap_and_the_mark_an_open_one(client: TestClient) -> None:
    now = _now()
    assert client.get("/api/v1/grid/gaps/999/hits").status_code == 404

    async def go(db: Any) -> int:
        row = await grid_gaps.open_probe_gap(db, started_at=now - timedelta(hours=2), detail="x")
        return int(row.id)

    gap_id = _run(client, go)
    res = client.post(f"/api/v1/grid/gaps/{gap_id}/hits/benign", json={}, headers=_ORIGIN)
    assert res.status_code == 409
    assert res.json()["detail"]["reason"] == "gap_open"


# ── the hold card ────────────────────────────────────────────────────────────


def test_the_analytic_names_the_gap_hits_that_broke_its_limit(client: TestClient) -> None:
    now = _now()

    async def go(db: Any) -> int:
        text = SPEC_TEXT + "fire_budget_per_day: 3\n"
        at = now - timedelta(days=5)
        await analytics_store.create_local(db, spec_text=text, by="analyst", now=at)
        await analytics_store.transition(
            db, _ID, to_status="shadow", by="analyst", why="try", now=at
        )
        await analytics_store.transition(db, _ID, to_status="live", by="analyst", why="ok", now=at)
        db.add_all(
            [
                _hit(
                    host=f"192.0.2.{i}",
                    born=now - timedelta(minutes=150),
                    start=now - timedelta(hours=27),
                    end=now - timedelta(hours=4),
                    spec_id=_ID,
                )
                for i in range(1, 6)
            ]
        )
        await db.commit()
        await self_heal.run_self_heal(db, now=now)
        row, _ = await grid_gaps.record_operator_gap(
            db,
            started_at=now - timedelta(days=4),
            ended_at=now - timedelta(hours=3),
            detail="",
            now=now,
        )
        return int(row.id)

    gap_id = _run(client, go)
    detail = client.get(f"/api/v1/analytics/{_ID}").json()
    assert detail["held_by_system"]
    hold = detail["gap_hold"]
    assert hold == {
        "analytic_id": _ID,
        "title": hold["title"],
        "hits": 5,
        "gap_hits": 5,
        "spike_hits": 0,
        "budget": 3,
        "return_offered": True,
        "gap_ids": [gap_id],
        "held_at": hold["held_at"],
    }
    review = client.get(f"/api/v1/grid/gaps/{gap_id}/hits").json()
    assert [h["analytic_id"] for h in review["held"]] == [_ID]
    # The approval stays the operator's click. Nothing moved the analytic.
    assert client.get(f"/api/v1/analytics/{_ID}").json()["status"] == "shadow"


# ── soc-ai grid-gaps ─────────────────────────────────────────────────────────


def _cli(monkeypatch: pytest.MonkeyPatch, settings: Settings, *argv: str) -> int:
    from soc_ai import cli

    monkeypatch.setattr("soc_ai.config.get_settings", lambda: settings)
    monkeypatch.setattr(sys, "argv", ["soc-ai", *argv])
    with pytest.raises(SystemExit) as exit_info:
        cli.main()
    return int(exit_info.value.code or 0)


def _gaps(settings: Settings) -> list[GridGap]:
    async def go() -> list[GridGap]:
        engine = make_engine(settings)
        await run_migrations(engine)
        async with make_sessionmaker(engine)() as db:
            rows = list((await db.scalars(select(GridGap))).all())
        await engine.dispose()
        return rows

    return asyncio.run(go())


def test_the_cli_adds_and_lists_an_operator_gap(
    settings_kratos: Settings,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    settings = settings_kratos.model_copy(update={"soc_ai_data_dir": tmp_path / "data"})
    now = _now()
    start, end = _z(now - timedelta(days=4)), _z(now - timedelta(hours=3))
    code = _cli(
        monkeypatch,
        settings,
        "grid-gaps",
        "add",
        "--start",
        start,
        "--end",
        end,
        "--detail",
        "The sensor VM was down.",
    )
    out = capsys.readouterr().out
    assert code == 0, out
    (row,) = _gaps(settings)
    assert row.source == "operator"
    assert row.detail == "The sensor VM was down."
    assert f"Recorded grid gap {row.id}" in out

    assert _cli(monkeypatch, settings, "grid-gaps", "list") == 0
    listed = capsys.readouterr().out
    assert f"{row.id}" in listed and "operator" in listed

    bad = _cli(monkeypatch, settings, "grid-gaps", "add", "--start", end, "--end", start)
    err = capsys.readouterr().err
    assert bad == 2
    assert "The end must be later than the start." in err
    assert len(_gaps(settings)) == 1
