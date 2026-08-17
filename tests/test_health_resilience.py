"""Health-probe resilience + status notifications (dogfood 2026-08-05).

With Security Onion down, /health previously rode the ES client's ~90s
timeout+retry stack — making the endpoint the UI's degraded-mode banner keys
off the slowest thing on the page, while N concurrent polls against a cold
cache launched N parallel hanging probes. The bell also had no notion of
system status at all.

The bell is also where a host-dossier disagreement is DELIVERED. The network
sweep fires exactly one rate-limited prod per standing conflict; before it had a
surface here, firing meant incrementing a counter and nothing else — the 14-day
rate limit and the "keep mine" backoff advanced against questions no operator
was ever shown.
"""

from __future__ import annotations

import asyncio
from datetime import timedelta
from types import SimpleNamespace
from typing import Any
from unittest.mock import patch

from pydantic import SecretStr
from soc_ai.api.webui import routes_meta
from soc_ai.config import Settings
from soc_ai.store import auth as auth_svc
from soc_ai.store import host_dossier as dossier_store
from soc_ai.store.db import make_engine, make_sessionmaker, run_migrations


def _settings(**over) -> Settings:
    kwargs = {
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


async def _ok_probe(*_a, **_k):
    return {"ok": True, "detail": "up"}


def test_hanging_es_probe_is_bounded_and_reads_as_down(monkeypatch):
    """A wedged ES ping must resolve to ok=False within the leg bound, not
    hang /health for the ES client's full timeout+retry stack."""

    async def hangs(*_a, **_k):
        await asyncio.sleep(3600)

    monkeypatch.setattr(routes_meta.probes, "probe_es", hangs)
    monkeypatch.setattr(routes_meta.probes, "probe_llm", _ok_probe)
    monkeypatch.setattr(routes_meta, "_HEALTH_PROBE_LEG_TIMEOUT_S", 0.1)

    state = SimpleNamespace(elastic=object())

    async def go():
        return await asyncio.wait_for(
            routes_meta._cached_health_probes(state, _settings()), timeout=5
        )

    probed = asyncio.run(go())
    assert probed["es"]["ok"] is False
    assert "treating as down" in probed["es"]["detail"]
    assert probed["llm"]["ok"] is True


def test_concurrent_cold_cache_probes_single_flight(monkeypatch):
    """N concurrent /health polls on a cold cache must run ONE probe, not N —
    parallel hanging probes were half of the SO-down freeze."""
    calls = []

    async def counting_probe(*_a, **_k):
        calls.append(1)
        await asyncio.sleep(0.05)
        return {"ok": True, "detail": "up"}

    monkeypatch.setattr(routes_meta.probes, "probe_es", counting_probe)
    monkeypatch.setattr(routes_meta.probes, "probe_llm", _ok_probe)

    state = SimpleNamespace(elastic=object())

    async def go():
        await asyncio.gather(
            *[routes_meta._cached_health_probes(state, _settings()) for _ in range(5)]
        )

    asyncio.run(go())
    assert len(calls) == 1


def test_dep_transitions_tracked_and_cleared():
    """down flip records a since-timestamp; recovery clears it; a still-down
    dep keeps its ORIGINAL flip time (stable notification id per outage)."""
    state = SimpleNamespace()
    routes_meta._note_dep_transitions(state, {"es": {"ok": False}, "llm": {"ok": True}})
    first = state._dep_down_since["es"]
    assert "llm" not in state._dep_down_since

    routes_meta._note_dep_transitions(state, {"es": {"ok": False}, "llm": {"ok": True}})
    assert state._dep_down_since["es"] == first  # unchanged mid-outage

    routes_meta._note_dep_transitions(state, {"es": {"ok": True}, "llm": {"ok": True}})
    assert "es" not in state._dep_down_since


# ── /health tells the same story the alert reads tell (dogfood 2026-08-14, D1) ─
#
# The topbar pill has no logic of its own — it renders whatever /health says —
# so these assert the PAYLOAD. On a grid answering 200 having read 2 of its 4
# shards, /health used to report `es.ok: true` (the probe only pinged) while
# every GET /api/v1/alerts on the same instance was a 503.


def _health_es(tmp_path, *, shards_failed):
    """`/health`'s ES component against a grid failing that many of 4 shards.

    The real :class:`ElasticClient` over a stubbed transport, so the assertion
    rides the production path: search response → ``_check_complete`` →
    ``GridPartialResultsError`` → probe → payload.
    """
    from unittest.mock import AsyncMock

    from fastapi.testclient import TestClient
    from soc_ai.main import create_app

    settings = _settings(db_path=str(tmp_path / "h.db"), events_index_pattern="logs-*")
    fake_es = AsyncMock()
    fake_es.info.return_value = {"cluster_name": "demo-grid", "version": {"number": "8.14.3"}}
    fake_es.search.return_value = {
        "took": 3,
        "timed_out": False,
        "_shards": {"total": 4, "successful": 4 - shards_failed, "failed": shards_failed},
        "hits": {"total": {"value": 0, "relation": "eq"}, "hits": []},
    }
    with (
        patch("soc_ai.so_client.elastic.AsyncElasticsearch", return_value=fake_es),
        patch("soc_ai.main.make_auth", return_value=AsyncMock()),
        patch("soc_ai.main.get_settings", return_value=settings),
        patch("soc_ai.webui.probes.probe_llm", new=_ok_probe),
    ):
        app = create_app()
        with TestClient(app) as client:
            return client.get("/api/v1/health").json()["es"]


def test_half_read_grid_reports_es_down_on_health(tmp_path):
    """2 of 4 shards failed → the ES dependency reads DOWN, so the topbar
    renders "1 degraded" instead of a green "connected"."""
    es = _health_es(tmp_path, shards_failed=2)
    assert es["ok"] is False


def test_whole_read_grid_still_reports_es_up_on_health(tmp_path):
    """The negative control: a grid that reads every shard stays green."""
    es = _health_es(tmp_path, shards_failed=0)
    assert es["ok"] is True


def test_health_carries_the_failure_class_for_the_banner(tmp_path):
    """The banner headline is chosen from `kind`, so /health has to carry it."""
    es = _health_es(tmp_path, shards_failed=2)
    assert es["kind"] == "partial"


def test_health_omits_the_failure_class_when_there_is_nothing_to_classify(tmp_path):
    """Present MEANS identified. A healthy component's payload is unchanged, so
    a client that never heard of `kind` reads exactly what it read before."""
    assert "kind" not in _health_es(tmp_path, shards_failed=0)


def test_down_dep_kind_is_recorded_and_refreshed_while_down():
    """The bell's title tracks the CURRENT trouble; the id (flip time) does not
    move, so an outage that changes character keeps one dismissible entry."""
    state = SimpleNamespace()
    routes_meta._note_dep_transitions(state, {"es": {"ok": False, "kind": "refused"}})
    first = state._dep_down_since["es"]
    assert state._dep_down_kind["es"] == "refused"

    routes_meta._note_dep_transitions(state, {"es": {"ok": False, "kind": "overloaded"}})
    assert state._dep_down_kind["es"] == "overloaded"
    assert state._dep_down_since["es"] == first

    routes_meta._note_dep_transitions(state, {"es": {"ok": True}})
    assert "es" not in state._dep_down_kind


def test_notifications_carry_down_dep_entries(tmp_path):
    """The bell lists a standing danger entry for a down dependency, with an
    outage-stable id — without ever probing ES from the notifications path."""
    from unittest.mock import AsyncMock

    from fastapi.testclient import TestClient
    from soc_ai.main import create_app

    settings = _settings(db_path=str(tmp_path / "n.db"))
    fake_es = AsyncMock()
    fake_auth = AsyncMock()
    with (
        patch("soc_ai.so_client.elastic.AsyncElasticsearch", return_value=fake_es),
        patch("soc_ai.main.make_auth", return_value=fake_auth),
        patch("soc_ai.main.get_settings", return_value=settings),
    ):
        app = create_app()
        with TestClient(app) as client:
            from soc_ai.store import auth as auth_svc

            app.state._dep_down_since = {"es": auth_svc.utcnow()}
            notifs = client.get("/api/v1/notifications").json()
            down = [n for n in notifs if n["id"].startswith("dep-down:es:")]
            assert len(down) == 1
            assert down[0]["tone"] == "danger"
            assert "unreachable" in down[0]["title"]

            # A saturated grid is announced as what it is. "unreachable" is for
            # a grid that is not answering; this one is, and is shedding load.
            app.state._dep_down_kind = {"es": "overloaded"}
            saturated = client.get("/api/v1/notifications").json()
            title = next(n["title"] for n in saturated if n["id"].startswith("dep-down:es:"))
            assert "unreachable" not in title
            assert "shedding load" in title

            # Recovery: the entry disappears.
            app.state._dep_down_since = {}
            notifs2 = client.get("/api/v1/notifications").json()
            assert not [n for n in notifs2 if n["id"].startswith("dep-down:")]


# ── Host-dossier conflict prods ────────────────────────────────────────────


_HYPERVISOR = "192.168.10.202"


async def _dossier_db(tmp_path: Any, **over: Any) -> tuple[Any, Settings]:
    """A scratch DB migrated to head, plus the settings that point at it."""
    settings = _settings(db_path=str(tmp_path / "dossier.db"), **over)
    engine = make_engine(settings)
    await run_migrations(engine)
    return make_sessionmaker(engine), settings


async def _seed_conflict(
    maker: Any,
    ip: str,
    *,
    prompt_count: int,
    field: str = "os_family",
    observations: int = 3,
) -> None:
    """One host whose telemetry keeps disagreeing with a standing override.

    ``prompt_count`` is the state the sweep would have left behind: 0 means the
    disagreement is real but the prod machine has not fired yet.
    """
    async with maker() as db:
        await dossier_store.upsert_host(db, ip)
        await db.commit()
    async with maker() as db:
        await dossier_store.set_override(db, ip, field, "windows", actor="analyst")
        row = await dossier_store.get_field(db, ip, field)
        row.inferred_value = "linux"
        row.inferred_confidence = 0.9
        row.conflict_kind = "mismatch"
        row.conflict_first_seen_at = auth_svc.utcnow() - timedelta(days=21)
        row.conflict_observations = observations
        row.conflict_prompt_count = prompt_count
        row.conflict_last_prompted_at = (
            auth_svc.utcnow() - timedelta(hours=2) if prompt_count else None
        )
        await db.commit()


def _request(maker: Any, settings: Settings) -> Any:
    """The two attributes ``list_notifications`` reads off the app."""
    return SimpleNamespace(
        app=SimpleNamespace(state=SimpleNamespace(db_sessionmaker=maker, settings=settings))
    )


async def test_a_fired_dossier_conflict_reaches_the_bell(tmp_path) -> None:
    """THE delivery gap: the prod advanced its own rate limit and showed nobody.

    Firing writes ``conflict_last_prompted_at`` and ``conflict_prompt_count``, so
    an invisible prod burns the 14-day interval and escalates the "keep mine"
    backoff — by the time the operator finds the conflict by hand, the first
    question they are actually asked already carries a 90-day snooze.
    """
    maker, settings = await _dossier_db(tmp_path)
    await _seed_conflict(maker, _HYPERVISOR, prompt_count=1)

    notifs = await routes_meta.list_notifications(_request(maker, settings))

    entries = [n for n in notifs if n.id.startswith("dossier-conflict:")]
    assert len(entries) == 1
    entry = entries[0]
    assert entry.id == f"dossier-conflict:{_HYPERVISOR}:os_family:1"
    assert entry.tone == "warn"
    assert entry.href == f"/entity/{_HYPERVISOR}"
    assert "os_family" in entry.title and _HYPERVISOR in entry.title


async def test_a_conflict_the_machine_has_not_raised_yet_stays_quiet(tmp_path) -> None:
    """The bell mirrors the rate-limited state machine, not every disagreement.

    A row that has never fired (prodding turned off, or the interval not yet
    elapsed) belongs on the conflicts list, not in the operator's face.
    """
    maker, settings = await _dossier_db(tmp_path)
    await _seed_conflict(maker, _HYPERVISOR, prompt_count=0)

    notifs = await routes_meta.list_notifications(_request(maker, settings))

    assert [n for n in notifs if n.id.startswith("dossier-conflict:")] == []


async def test_the_conflict_notification_id_is_keyed_on_the_prompt_cycle(tmp_path) -> None:
    """A dismissal must hold for THIS prod and not swallow the next one.

    Bell dismissals are client-side and keyed on the id, so an id that stayed
    the same across cycles would mean an operator who dismissed once never sees
    that conflict raised again — the same silent-forever failure in a different
    place.
    """
    maker, settings = await _dossier_db(tmp_path)
    await _seed_conflict(maker, _HYPERVISOR, prompt_count=1)
    first = await routes_meta.list_notifications(_request(maker, settings))

    async with maker() as db:
        row = await dossier_store.get_field(db, _HYPERVISOR, "os_family")
        row.conflict_prompt_count = 2
        await db.commit()
    second = await routes_meta.list_notifications(_request(maker, settings))

    ids = {n.id for n in first} | {n.id for n in second}
    assert len([i for i in ids if i.startswith("dossier-conflict:")]) == 2


async def test_the_bell_survives_a_dossier_read_failure(tmp_path) -> None:
    """The bell is polled every 15s and must keep working when a part is broken."""
    maker, settings = await _dossier_db(tmp_path)
    await _seed_conflict(maker, _HYPERVISOR, prompt_count=1)

    async def _boom(*_a: Any, **_k: Any) -> Any:
        raise RuntimeError("no such table: host_dossier_field")

    with patch.object(routes_meta.dossier_svc, "conflicts_due", _boom):
        notifs = await routes_meta.list_notifications(_request(maker, settings))

    assert [n for n in notifs if n.id.startswith("dossier-conflict:")] == []


async def test_the_master_switch_takes_the_conflict_off_the_bell(tmp_path) -> None:
    """With the feature off its prods are not the operator's problem."""
    maker, settings = await _dossier_db(tmp_path, dossier_enabled=False)
    await _seed_conflict(maker, _HYPERVISOR, prompt_count=1)

    notifs = await routes_meta.list_notifications(_request(maker, settings))

    assert [n for n in notifs if n.id.startswith("dossier-conflict:")] == []
