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
import contextlib
from datetime import timedelta
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, patch

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
    assert "soc-ai treats it as down." in probed["es"]["detail"]
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


def test_concurrent_cold_cache_pcap_probe_single_flight(monkeypatch):
    """The pcap leg spawns an ssh login per probe, so N concurrent polls on a
    cold cache must share ONE in-flight probe, not fork N ssh children
    against a sensor that may already be the thing that is slow."""
    calls = []

    async def counting_probe(*_a, **_k):
        calls.append(1)
        await asyncio.sleep(0.05)
        return {"ok": True, "detail": "up"}

    monkeypatch.setattr(routes_meta.probes, "probe_pcap", counting_probe)

    state = SimpleNamespace()

    async def go():
        return await asyncio.gather(
            *[routes_meta._cached_pcap_probe(state, _settings()) for _ in range(5)]
        )

    results = asyncio.run(go())
    assert len(calls) == 1
    assert all(r == {"ok": True, "detail": "up"} for r in results)


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


def _health_es(tmp_path, *, shards_failed, fail_on_partial=True):
    """`/health`'s ES component against a grid failing that many of 4 shards.

    The real :class:`ElasticClient` over a stubbed transport, so the assertion
    rides the production path: search response → ``_check_complete`` →
    ``GridPartialResultsError`` → probe → payload.

    ``fail_on_partial`` sets the operator opt-out ``es_fail_on_partial_results``,
    which governs what a QUERY does about a partial read and must not govern
    whether the probe says so.
    """

    from fastapi.testclient import TestClient
    from soc_ai.main import create_app

    settings = _settings(
        db_path=str(tmp_path / "h.db"),
        events_index_pattern="logs-*",
        es_fail_on_partial_results=fail_on_partial,
    )
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


# ── The partial-read opt-out governs the query, never the telling ───────────
#
# `es_fail_on_partial_results=False` exists so an operator with a chronically
# red shard can keep working off the surviving ones. It rode the same code path
# as the health probe, so switching it on also switched OFF the only surface
# that would have told them the grid was half-read: /health went green, the
# topbar said connected, and the bell had nothing to say. The operator who
# accepted partial ANSWERS had, without being asked, also accepted silence
# about the cause.


def test_the_partial_read_opt_out_does_not_silence_the_health_probe(tmp_path):
    """Opt-out ON, 2 of 4 shards failed: the probe still reports the grid down.

    The probe is the diagnostic, not a query. Its job is to say what the grid is
    doing, and a tolerance for short answers elsewhere cannot buy silence here.
    """
    es = _health_es(tmp_path, shards_failed=2, fail_on_partial=False)
    assert es["ok"] is False
    assert es["kind"] == "partial"


def test_the_opt_out_still_leaves_a_whole_read_grid_green(tmp_path):
    """The over-correction control: the opt-out must not make the probe pessimistic.

    A grid that reads every shard is green whatever the setting says, so the
    fix cannot be "always report partial".
    """
    es = _health_es(tmp_path, shards_failed=0, fail_on_partial=False)
    assert es["ok"] is True
    assert "kind" not in es


def test_the_opt_out_is_invisible_to_health(tmp_path):
    """Same grid, same /health answer, whichever way the operator set it."""
    assert _health_es(tmp_path, shards_failed=2, fail_on_partial=True) == _health_es(
        tmp_path, shards_failed=2, fail_on_partial=False
    )


def test_a_half_read_grid_under_the_opt_out_still_reaches_the_bell(tmp_path):
    """The notification is derived from the probe, so it inherits the silence.

    Drives /health first (which is what records the transition) and then reads
    the bell, so this pins the whole chain an operator would actually see.
    """

    from fastapi.testclient import TestClient
    from soc_ai.main import create_app

    settings = _settings(
        db_path=str(tmp_path / "b.db"),
        events_index_pattern="logs-*",
        es_fail_on_partial_results=False,
    )
    fake_es = AsyncMock()
    fake_es.info.return_value = {"cluster_name": "demo-grid", "version": {"number": "8.14.3"}}
    fake_es.search.return_value = {
        "took": 3,
        "timed_out": False,
        "_shards": {"total": 4, "successful": 2, "failed": 2},
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
            assert client.get("/api/v1/health").json()["es"]["ok"] is False
            notifs = client.get("/api/v1/notifications").json()
    down = [n for n in notifs if n["id"].startswith("dep-down:es:")]
    assert len(down) == 1
    assert "reading only part of the grid" in down[0]["title"]


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


def test_notifications_carry_a_broken_audit_trail(tmp_path):
    """A broken audit chain is a standing bell entry, with no index read.

    This is the only channel a tamper finding has on a stock install: the
    notification webhook is off by default. It is served from the scheduled
    verification's in-memory alarm slot, so a 15-second poll never touches the
    audit index — least of all when the audit index is the thing in trouble.
    """

    from fastapi.testclient import TestClient
    from soc_ai.api.webui.routes_config import _get_audit_verify_status
    from soc_ai.main import create_app

    settings = _settings(db_path=str(tmp_path / "audit-bell.db"))
    fake_es = AsyncMock()
    fake_auth = AsyncMock()
    with (
        patch("soc_ai.so_client.elastic.AsyncElasticsearch", return_value=fake_es),
        patch("soc_ai.main.make_auth", return_value=fake_auth),
        patch("soc_ai.main.get_settings", return_value=settings),
    ):
        app = create_app()
        with TestClient(app) as client:
            status = _get_audit_verify_status(app.state)
            status.alarm = {
                "detected_at": "2026-09-06T12:00:00+00:00",
                "break_kind": "duplicate_seq",
                "break_detail": "2 records claim sequence 109667",
            }
            notifs = client.get("/api/v1/notifications").json()
            broken = [n for n in notifs if n["id"].startswith("audit-chain-break:")]
            assert len(broken) == 1
            assert broken[0]["tone"] == "danger"
            assert "duplicate_seq" in broken[0]["title"]
            assert broken[0]["href"] == "/config"

            # A clean verification clears the slot; the entry goes with it.
            status.alarm = None
            after = client.get("/api/v1/notifications").json()
            assert not [n for n in after if n["id"].startswith("audit-chain-break:")]


def test_the_audit_trail_alarm_can_actually_be_dismissed(tmp_path):
    """The bell entry's identity is the finding, not the moment it was noticed.

    Keyed on the detection stamp, every run minted a new id and the entry could
    not be cleared: an undismissable danger notification every day until a
    forked stretch of history aged out of the seven-day window, which was
    several days away. Keyed on the finding, a dismissal holds and a new break
    arrives undismissed.
    """

    from fastapi.testclient import TestClient
    from soc_ai.api.webui.routes_config import _get_audit_verify_status
    from soc_ai.main import create_app

    settings = _settings(db_path=str(tmp_path / "audit-bell-dismiss.db"))
    fake_es = AsyncMock()
    fake_auth = AsyncMock()

    def _alarm(**over):
        base = {
            "detected_at": "2026-09-06T12:00:00+00:00",
            "alarm_key": "duplicate_seq|2026-09-04T19:07:04Z|0",
            "alarm_since": "2026-09-04T19:07:04+00:00",
            "break_kind": "duplicate_seq",
            "break_detail": "2 records claim sequence 109667",
            "blast_radius": (
                "41 sequence numbers claimed by more than one record, across 51 "
                "extra records, up to 4 writers at one position. No record was "
                "altered: every copy still matches its own hash."
            ),
            "dismissible": True,
            # The scan window the scheduled check used. Without it the bell and
            # the CLI answer different questions in the same-shaped sentence.
            "window_days": 7,
        }
        base.update(over)
        return base

    def _entry(client):
        rows = [
            n
            for n in client.get("/api/v1/notifications").json()
            if n["id"].startswith("audit-chain-break:")
        ]
        assert len(rows) == 1
        return rows[0]

    with (
        patch("soc_ai.so_client.elastic.AsyncElasticsearch", return_value=fake_es),
        patch("soc_ai.main.make_auth", return_value=fake_auth),
        patch("soc_ai.main.get_settings", return_value=settings),
    ):
        app = create_app()
        with TestClient(app) as client:
            status = _get_audit_verify_status(app.state)

            status.alarm = _alarm()
            first = _entry(client)
            assert first["id"] == "audit-chain-break:duplicate_seq|2026-09-04T19:07:04Z|0"
            assert first["dismissible"] is True
            # The scale reaches the operator, not one sequence number out of 41.
            assert "41 sequence numbers" in first["title"]
            # And it is DATED. This slot holds the last scheduled verification's
            # numbers, which the loop refreshes on its own cadence, so the bell
            # can carry a smaller population than a scan run right now — on the
            # range it read four duplicated positions beside a CLI reporting six,
            # with nothing on either surface to say one was older. The fix is not
            # to hide the older number but to say when it was taken.
            assert "The check covered the last 7 days." in first["title"]

            # Tomorrow's run, same scar, later detection: the id must not move,
            # or yesterday's dismissal is undone.
            status.alarm = _alarm(detected_at="2026-09-07T12:00:00+00:00")
            assert _entry(client)["id"] == first["id"]

            # A record edited after the fact is a different finding, so the
            # fork's dismissal cannot cover it, and it is not dismissible at all.
            status.alarm = _alarm(
                alarm_key="content_altered+duplicate_seq|2026-09-07T08:00:00Z|1",
                break_kind="content_altered",
                dismissible=False,
            )
            altered = _entry(client)
            assert altered["id"] != first["id"]
            assert altered["dismissible"] is False


# ── The always-on pill must cover the write path (dogfood 2026-09-07, D1) ─────
#
# /health probed Elasticsearch and the model gateway only. The Security Onion
# web API, the path every acknowledge, escalate and case write travels, was
# not probed at all, so the header pill read "connected" in the same frame as a
# setup-health card reporting a Security Onion timeout. An always-on indicator
# that omits a whole upstream gives an optimistic answer in the worst place.


class _StubResponse:
    def __init__(self, status_code: int) -> None:
        self.status_code = status_code


class _StubSoAuth:
    """The one method of the shared SoAuthClient the probe uses."""

    def __init__(self, outcome: Any) -> None:
        self.outcome = outcome
        self.calls: list[tuple[str, str]] = []

    async def request(self, method: str, path: str, **_kw: Any) -> Any:
        self.calls.append((method, path))
        if isinstance(self.outcome, BaseException):
            raise self.outcome
        return self.outcome


def test_probe_so_api_reports_a_reachable_api():
    from soc_ai.webui import probes

    auth = _StubSoAuth(_StubResponse(200))
    result = asyncio.run(probes.probe_so_api(auth, _settings()))
    assert result["ok"] is True
    assert auth.calls == [("GET", "/api/info")]


def test_probe_so_api_classifies_a_hung_api_as_a_timeout():
    from soc_ai.webui import probes

    auth = _StubSoAuth(TimeoutError("read timed out"))
    result = asyncio.run(probes.probe_so_api(auth, _settings()))
    assert result["ok"] is False
    assert result["kind"] == probes.KIND_TIMEOUT


def test_probe_so_api_classifies_a_refused_api():
    from soc_ai.webui import probes

    auth = _StubSoAuth(ConnectionError("connection refused"))
    result = asyncio.run(probes.probe_so_api(auth, _settings()))
    assert result["ok"] is False
    assert result["kind"] == probes.KIND_REFUSED


def test_probe_so_api_reports_a_refusal_by_the_api_itself():
    """Reachable is not usable: a 403 on /api/info means every write 403s too."""
    from soc_ai.webui import probes

    auth = _StubSoAuth(_StubResponse(403))
    result = asyncio.run(probes.probe_so_api(auth, _settings()))
    assert result["ok"] is False
    assert "403" in result["detail"]


def test_probe_so_api_never_leaks_the_password():
    from soc_ai.webui import probes

    auth = _StubSoAuth(RuntimeError("login failed for https://user:hunter2@so.example.com"))
    result = asyncio.run(probes.probe_so_api(auth, _settings()))
    assert result["ok"] is False
    assert "hunter2" not in result["detail"]


def test_health_covers_the_security_onion_api(monkeypatch):
    """A down SO API must reach the payload the pill renders. The pill claims
    'connected', and every write travels this path."""

    async def so_down(*_a, **_k):
        return {"ok": False, "kind": "timeout", "detail": "took the request, never answered"}

    monkeypatch.setattr(routes_meta.probes, "probe_es", _ok_probe)
    monkeypatch.setattr(routes_meta.probes, "probe_llm", _ok_probe)
    monkeypatch.setattr(routes_meta.probes, "probe_so_api", so_down)

    state = SimpleNamespace(elastic=object(), auth=object())
    probed = asyncio.run(routes_meta._cached_health_probes(state, _settings()))
    assert probed["so"]["ok"] is False
    # And it joins the same down-dependency tracking ES and the gateway get, so
    # the bell carries the outage too.
    assert "so" in state._dep_down_since


def test_health_payload_carries_the_security_onion_component(tmp_path):
    """GET /api/v1/health names Security Onion as its own component."""

    from fastapi.testclient import TestClient
    from soc_ai.main import create_app

    settings = _settings(db_path=str(tmp_path / "so-health.db"))
    fake_es = AsyncMock()
    fake_es.info.return_value = {"cluster_name": "demo-grid", "version": {"number": "8.14.3"}}
    fake_es.search.return_value = {
        "took": 1,
        "timed_out": False,
        "_shards": {"total": 1, "successful": 1, "failed": 0},
        "hits": {"total": {"value": 0, "relation": "eq"}, "hits": []},
    }
    fake_auth = AsyncMock()
    fake_auth.request.return_value = _StubResponse(200)
    with (
        patch("soc_ai.so_client.elastic.AsyncElasticsearch", return_value=fake_es),
        patch("soc_ai.main.make_auth", return_value=fake_auth),
        patch("soc_ai.main.get_settings", return_value=settings),
        patch("soc_ai.webui.probes.probe_llm", new=_ok_probe),
    ):
        app = create_app()
        with TestClient(app) as client:
            body = client.get("/api/v1/health").json()
    assert body["so"]["ok"] is True


def test_notifications_name_the_security_onion_api(tmp_path):
    """A down SO API is a named bell entry, not a bare key."""

    from fastapi.testclient import TestClient
    from soc_ai.main import create_app

    settings = _settings(db_path=str(tmp_path / "so-bell.db"))
    with (
        patch("soc_ai.so_client.elastic.AsyncElasticsearch", return_value=AsyncMock()),
        patch("soc_ai.main.make_auth", return_value=AsyncMock()),
        patch("soc_ai.main.get_settings", return_value=settings),
    ):
        app = create_app()
        with TestClient(app) as client:
            app.state._dep_down_since = {"so": auth_svc.utcnow()}
            notifs = client.get("/api/v1/notifications").json()
    down = [n for n in notifs if n["id"].startswith("dep-down:so:")]
    assert len(down) == 1
    assert "Security Onion API" in down[0]["title"]


async def test_health_is_probed_on_a_schedule_with_no_client_polling() -> None:
    """A dependency outage must be noticed with no browser tab open.

    Every health surface here is pull-only behind a TTL cache, and
    `_note_dep_transitions` — the only thing that records a dependency going
    down, and the only thing that puts an entry on the bell — used to run purely
    as a side effect of a client polling /api/v1/health. An open tab was the
    scheduler: ES could be down all night, recover before anyone looked, and
    nothing anywhere would know.
    """
    from soc_ai import main as soc_main

    real_sleep = asyncio.sleep
    calls: list[object] = []

    async def _probe(state: object, settings: object) -> dict[str, dict[str, object]]:
        calls.append(state)
        return {}

    async def _fast_sleep(_seconds: float) -> None:
        # Yield, but do not actually wait the loop's minute. Keeps a real
        # scheduling point so the task and the test interleave.
        await real_sleep(0)

    app = SimpleNamespace(state=SimpleNamespace())
    with (
        patch("soc_ai.api.webui.routes_meta._cached_health_probes", _probe),
        patch.object(soc_main.asyncio, "sleep", _fast_sleep),
    ):
        task = asyncio.create_task(soc_main._health_probe_loop(app, SimpleNamespace()))
        while len(calls) < 3 and not task.done():
            await real_sleep(0)
        task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await task

    assert len(calls) >= 3, "the loop never probed: nothing would notice an overnight outage"
    assert calls[0] is app.state


async def test_a_failing_health_probe_does_not_kill_the_loop() -> None:
    """A probe that could not run is not a dependency being down, and one bad
    wake must not take out the only scheduled health check in the process."""
    from soc_ai import main as soc_main

    real_sleep = asyncio.sleep
    calls: list[int] = []

    async def _boom(state: object, settings: object) -> dict[str, dict[str, object]]:
        calls.append(1)
        raise RuntimeError("probe exploded")

    async def _fast_sleep(_seconds: float) -> None:
        await real_sleep(0)

    app = SimpleNamespace(state=SimpleNamespace())
    with (
        patch("soc_ai.api.webui.routes_meta._cached_health_probes", _boom),
        patch.object(soc_main.asyncio, "sleep", _fast_sleep),
    ):
        task = asyncio.create_task(soc_main._health_probe_loop(app, SimpleNamespace()))
        while len(calls) < 3 and not task.done():
            await real_sleep(0)
        still_running = not task.done()
        task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await task

    assert len(calls) >= 3, "the loop stopped after a failure"
    assert still_running
