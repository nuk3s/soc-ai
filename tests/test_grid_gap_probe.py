"""The probe source of the grid-gap ledger, GET /grid/gaps and the closed-gap bell row.

The range sensor was down from 2026-10-15 13:36Z to 2026-10-19 10:15Z. The
health probe saw it, the dependency-down row left the bell at the recovery,
and nothing recorded the outage (dogfood 2026-10-19, R1-D4). These tests pin
the stored record.
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, patch

from pydantic import SecretStr
from soc_ai.config import Settings
from soc_ai.store import grid_gaps
from soc_ai.store.db import make_engine, make_sessionmaker, run_migrations
from soc_ai.webui import grid_gap_probe

REFUSED = {"ok": False, "kind": "refused", "state": "down", "detail": "connection refused"}
TIMEOUT = {"ok": False, "kind": "timeout", "state": "slow", "detail": "no answer"}
SLOW = {"ok": False, "kind": "slow", "state": "slow", "detail": "answered late"}
GOOD = {"ok": True, "kind": "", "state": "ok", "detail": "up"}


def _settings(**over: Any) -> Settings:
    kwargs: dict[str, Any] = {
        "so_host": "https://so.example.com",
        "so_username": "analyst",
        "so_password": SecretStr("password123"),
        "so_verify_ssl": False,
        "es_hosts": ["https://so.example.com:9200"],
        "litellm_base_url": "http://localhost:4000",
        "api_auth_required": False,
    }
    kwargs.update(over)
    return Settings(**kwargs)


def _naive_now() -> datetime:
    return datetime.now(UTC).replace(tzinfo=None, microsecond=0)


async def _state(settings: Settings) -> tuple[Any, Any]:
    engine = make_engine(settings)
    await run_migrations(engine)
    return engine, SimpleNamespace(db_sessionmaker=make_sessionmaker(engine))


async def _gaps(state: Any) -> list[Any]:
    async with state.db_sessionmaker() as db:
        return await grid_gaps.overlapping(
            db, since=_naive_now() - timedelta(days=30), until=_naive_now() + timedelta(days=1)
        )


async def _feed(state: Any, results: list[tuple[datetime, dict[str, Any]]]) -> None:
    for at, es in results:
        await grid_gap_probe.note_probe(state, {"es": es}, now=at)


async def test_one_failed_probe_opens_no_gap(settings_kratos: Settings) -> None:
    engine, state = await _state(settings_kratos)
    t0 = _naive_now() - timedelta(hours=1)
    await _feed(state, [(t0, REFUSED), (t0 + timedelta(minutes=1), GOOD)])
    assert await _gaps(state) == []
    await engine.dispose()


async def test_a_slow_grid_opens_no_gap_however_long_it_lasts(settings_kratos: Settings) -> None:
    engine, state = await _state(settings_kratos)
    t0 = _naive_now() - timedelta(hours=2)
    await _feed(state, [(t0 + timedelta(minutes=n), SLOW) for n in range(30)])
    assert await _gaps(state) == []
    await engine.dispose()


async def test_answers_that_are_not_an_outage_open_no_gap(settings_kratos: Settings) -> None:
    engine, state = await _state(settings_kratos)
    t0 = _naive_now() - timedelta(hours=2)
    for kind in ("partial", "overloaded", "unreadable", ""):
        await _feed(
            state,
            [(t0 + timedelta(minutes=n), {"ok": False, "kind": kind}) for n in range(10)],
        )
    assert await _gaps(state) == []
    await engine.dispose()


async def test_an_unreadable_grid_opens_a_gap_at_the_first_failed_probe(
    settings_kratos: Settings,
) -> None:
    engine, state = await _state(settings_kratos)
    t0 = _naive_now() - timedelta(hours=3)
    await _feed(
        state, [(t0 + timedelta(minutes=n), REFUSED if n % 2 else TIMEOUT) for n in range(5)]
    )
    rows = await _gaps(state)
    assert len(rows) == 1
    assert rows[0].source == grid_gaps.SOURCE_PROBE
    assert rows[0].started_at == t0
    assert rows[0].ended_at is None

    back = t0 + timedelta(hours=2)
    await _feed(state, [(back, GOOD)])
    rows = await _gaps(state)
    assert rows[0].ended_at == back
    await engine.dispose()


async def test_an_open_gap_survives_a_restart_and_the_first_good_probe_closes_it(
    settings_kratos: Settings,
) -> None:
    engine, state = await _state(settings_kratos)
    t0 = _naive_now() - timedelta(hours=5)
    await _feed(state, [(t0 + timedelta(minutes=n), REFUSED) for n in range(4)])
    assert len(await _gaps(state)) == 1

    # A new process: no memory, the same store. The grid is still down.
    restarted = SimpleNamespace(db_sessionmaker=state.db_sessionmaker)
    later = t0 + timedelta(hours=1)
    await _feed(restarted, [(later + timedelta(minutes=n), REFUSED) for n in range(5)])
    rows = await _gaps(restarted)
    assert len(rows) == 1
    assert rows[0].started_at == t0

    back = t0 + timedelta(hours=4)
    await _feed(restarted, [(back, GOOD)])
    rows = await _gaps(restarted)
    assert len(rows) == 1
    assert rows[0].ended_at == back
    await engine.dispose()


async def test_the_demo_records_no_gap(settings_kratos: Settings) -> None:
    engine, state = await _state(settings_kratos)
    state.settings = SimpleNamespace(soc_ai_demo=True)
    t0 = _naive_now() - timedelta(hours=1)
    await _feed(state, [(t0 + timedelta(minutes=n), REFUSED) for n in range(10)])
    assert await _gaps(state) == []
    await engine.dispose()


async def test_a_state_with_no_store_records_nothing_and_does_not_raise() -> None:
    await grid_gap_probe.note_probe(SimpleNamespace(), {"es": REFUSED})


async def test_the_health_probe_records_the_gap(
    settings_kratos: Settings, monkeypatch: Any
) -> None:
    """The ledger is fed by the same cached probe the pill and the bell read."""
    from soc_ai.api.webui import routes_meta

    async def refused(*_a: Any, **_k: Any) -> dict[str, Any]:
        return {"ok": False, "kind": "refused", "detail": "connection refused"}

    async def ok(*_a: Any, **_k: Any) -> dict[str, Any]:
        return {"ok": True, "detail": "up"}

    monkeypatch.setattr(routes_meta.probes, "probe_es", refused)
    monkeypatch.setattr(routes_meta.probes, "probe_llm", ok)
    monkeypatch.setattr(routes_meta.probes, "probe_so_api", ok)
    monkeypatch.setattr(grid_gap_probe, "CONFIRM", timedelta(0))
    engine, state = await _state(settings_kratos)
    state.elastic = object()
    await routes_meta._cached_health_probes(state, settings_kratos)
    rows = await _gaps(state)
    assert len(rows) == 1
    assert rows[0].ended_at is None
    await engine.dispose()


# ── GET /grid/gaps and the bell row ──────────────────────────────────────────


def _seed(settings: Settings, rows: list[dict[str, Any]]) -> None:
    async def go() -> None:
        engine = make_engine(settings)
        await run_migrations(engine)
        maker = make_sessionmaker(engine)
        async with maker() as db:
            for row in rows:
                if row.get("source") == grid_gaps.SOURCE_SWEEP:
                    await grid_gaps.record_sweep_gap(
                        db,
                        plane=row["plane"],
                        started_at=row["started_at"],
                        ended_at=row["ended_at"],
                        detail="sweep",
                    )
                    continue
                await grid_gaps.open_probe_gap(db, started_at=row["started_at"], detail="refused")
                if row.get("ended_at") is not None:
                    await grid_gaps.close_probe_gaps(db, ended_at=row["ended_at"])
        await engine.dispose()

    asyncio.run(go())


def _client_get(settings: Settings, *paths: str) -> list[Any]:
    from fastapi.testclient import TestClient
    from soc_ai.main import create_app

    with (
        patch("soc_ai.so_client.elastic.AsyncElasticsearch", return_value=AsyncMock()),
        patch("soc_ai.main.make_auth", return_value=AsyncMock()),
        patch("soc_ai.main.get_settings", return_value=settings),
    ):
        app = create_app()
        with TestClient(app) as client:
            return [client.get(p) for p in paths]


def test_the_gaps_route_returns_the_gaps_that_overlap_the_window(tmp_path: Any) -> None:
    settings = _settings(db_path=str(tmp_path / "g.db"))
    now = _naive_now()
    _seed(
        settings,
        [
            {"started_at": now - timedelta(days=20), "ended_at": now - timedelta(days=19)},
            {"started_at": now - timedelta(hours=96), "ended_at": now - timedelta(hours=3)},
            {
                "source": grid_gaps.SOURCE_SWEEP,
                "plane": "connection_rate",
                "started_at": now - timedelta(hours=2),
                "ended_at": now - timedelta(hours=1),
            },
        ],
    )
    since = (now - timedelta(days=7)).isoformat() + "Z"
    (week, default, bad) = _client_get(
        settings,
        f"/api/v1/grid/gaps?since={since}",
        "/api/v1/grid/gaps",
        "/api/v1/grid/gaps?since=yesterday",
    )
    body = week.json()
    assert week.status_code == 200
    assert [g["source"] for g in body["gaps"]] == ["probe", "sweep"]
    probe = body["gaps"][0]
    assert probe["open"] is False
    assert probe["duration_s"] == 93 * 3600
    assert probe["ended_at"].endswith("Z")
    assert body["gaps"][1]["plane"] == "connection_rate"
    # No window named: the last 7 days.
    assert len(default.json()["gaps"]) == 2
    assert bad.status_code == 400


def test_an_open_gap_reads_open_with_its_length_so_far(tmp_path: Any) -> None:
    settings = _settings(db_path=str(tmp_path / "o.db"))
    _seed(settings, [{"started_at": _naive_now() - timedelta(hours=2)}])
    (resp,) = _client_get(settings, "/api/v1/grid/gaps")
    (gap,) = resp.json()["gaps"]
    assert gap["open"] is True
    assert gap["ended_at"] is None
    assert 2 * 3600 - 60 <= gap["duration_s"] <= 2 * 3600 + 120


def test_a_closed_gap_stays_in_the_bell_for_24_hours(tmp_path: Any) -> None:
    settings = _settings(db_path=str(tmp_path / "b.db"))
    now = _naive_now()
    _seed(
        settings,
        [
            # Closed 30 h ago: out of the bell.
            {"started_at": now - timedelta(hours=60), "ended_at": now - timedelta(hours=30)},
            # Closed 1 h ago: in the bell.
            {"started_at": now - timedelta(hours=94), "ended_at": now - timedelta(hours=1)},
        ],
    )
    (resp,) = _client_get(settings, "/api/v1/notifications")
    rows = [n for n in resp.json() if n["id"].startswith("grid-gap:")]
    assert len(rows) == 1
    (row,) = rows
    assert row["tone"] == "accent"
    start = grid_gaps.stamp(now - timedelta(hours=94))
    end = grid_gaps.stamp(now - timedelta(hours=1))
    assert row["title"] == (
        f"The grid was unreadable from {start} to {end}. Counts over these hours are incomplete."
    )


def test_an_open_gap_writes_no_closed_gap_row(tmp_path: Any) -> None:
    settings = _settings(db_path=str(tmp_path / "x.db"))
    _seed(settings, [{"started_at": _naive_now() - timedelta(hours=2)}])
    (resp,) = _client_get(settings, "/api/v1/notifications")
    assert not [n for n in resp.json() if n["id"].startswith("grid-gap:")]
