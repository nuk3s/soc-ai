"""Tests for the SOC_AI_DEMO flag (env-only, not UI-editable) + egress guard."""

import json
import time
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient
from soc_ai.agent.models import build_synthesizer_model
from soc_ai.config import Settings
from soc_ai.demo.guard import DemoEgressBlocked, assert_egress_allowed
from soc_ai.main import create_app
from soc_ai.so_client.elastic import ElasticClient
from soc_ai.store.config_overrides import is_editable

from tests.conftest import _base_settings_kwargs


def _demo_settings(**overrides):
    """Settings with the demo flag on; extra constructor kwargs via overrides."""
    return Settings(**{**_base_settings_kwargs(), **overrides}).model_copy(
        update={"soc_ai_demo": True}
    )


@contextmanager
def _app_client(settings: Settings) -> Iterator[TestClient]:
    """App-factory TestClient (same patch set as tests/test_api_auth.py)."""
    with (
        patch("soc_ai.so_client.elastic.AsyncElasticsearch", return_value=AsyncMock()),
        patch("soc_ai.main.make_auth", return_value=AsyncMock()),
        patch("soc_ai.main.get_settings", return_value=settings),
    ):
        app = create_app()
        with TestClient(app) as client:
            yield client


def _demo_app_settings() -> Settings:
    """Demo settings safe for app startup: the lifespan constructs ElasticClient,
    which in demo mode refuses non-loopback es_hosts (the bundled mock ES is the
    intended demo deployment shape)."""
    return _demo_settings(es_hosts=["http://127.0.0.1:9200"])


def _is_demo_refusal(resp) -> bool:
    if resp.status_code != 403:
        return False
    detail = resp.json().get("detail")
    return isinstance(detail, dict) and detail.get("reason") == "demo_mode"


def test_demo_flag_defaults_off():
    s = Settings(**_base_settings_kwargs())
    assert s.soc_ai_demo is False


def test_demo_flag_from_env(monkeypatch):
    monkeypatch.setenv("SOC_AI_DEMO", "true")
    s = Settings(**_base_settings_kwargs())
    assert s.soc_ai_demo is True


def test_demo_flag_not_ui_editable():
    assert not is_editable("soc_ai_demo")


def test_guard_raises_in_demo():
    with pytest.raises(DemoEgressBlocked):
        assert_egress_allowed(_demo_settings(), "llm gateway")


def test_guard_passes_outside_demo():
    assert_egress_allowed(Settings(**_base_settings_kwargs()), "llm gateway")


def test_llm_provider_blocked_in_demo():
    with pytest.raises(DemoEgressBlocked):
        build_synthesizer_model(_demo_settings())


def test_elastic_loopback_only_in_demo():
    # ElasticClient reads es_hosts (not so_host) — a non-loopback host refuses.
    with pytest.raises(DemoEgressBlocked):
        ElasticClient(_demo_settings(es_hosts=["https://192.0.2.253:9200"]))
    # loopback allowed — the bundled mock ES
    ElasticClient(_demo_settings(es_hosts=["http://127.0.0.1:9200"]))


# ---------------------------------------------------------------------------
# Read-only middleware: mutating requests get a structured 403 in demo mode.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("method", ["POST", "PUT", "PATCH", "DELETE"])
def test_demo_blocks_writes(method):
    with _app_client(_demo_app_settings()) as client:
        r = client.request(method, "/api/v1/alerts/ack-group", json={})
        assert r.status_code == 403
        assert r.json()["detail"]["reason"] == "demo_mode"
        assert "hint" in r.json()["detail"]
        # The refusal is the most-served mutating response on a public demo —
        # it must flow back out through the _security_headers middleware.
        assert r.headers["x-content-type-options"] == "nosniff"
        assert r.headers["x-frame-options"] == "DENY"


def test_demo_allows_reads():
    with _app_client(_demo_app_settings()) as client:
        assert client.get("/healthz").status_code == 200


def test_writes_open_outside_demo():
    with _app_client(Settings(**_base_settings_kwargs())) as client:
        r = client.post("/api/v1/alerts/ack-group", json={})
        assert not _is_demo_refusal(r)


# Replay-trigger allowlist: Task 6 turns these POSTs into fixture replays, so
# demo mode must NOT refuse them. They may still fail for other reasons (empty
# body -> 422) — assert only that the demo refusal is not what comes back.
# Verified mounted paths: /investigate (soc_ai/api/routes.py router, included
# with NO prefix at main.py) and /api/v1/hunt (webui hunts router).
@pytest.mark.parametrize("path", ["/investigate", "/api/v1/hunt"])
def test_demo_allowlists_replay_triggers(path):
    with _app_client(_demo_app_settings()) as client:
        r = client.post(path, json={})
        assert not _is_demo_refusal(r)
        # Pin that the allowlisted route actually exists — a shared path typo
        # here and in _DEMO_WRITE_ALLOW would otherwise pass silently.
        assert r.status_code != 404


# Chat POSTs (investigation + hunt about) carry a variable id and are turned into
# canned zero-egress replies by the manager demo branches — demo mode must NOT
# refuse them. They may still 404/422 for other reasons; assert only that the
# demo refusal is not what comes back.
@pytest.mark.parametrize(
    "path",
    [
        "/api/v1/investigations/demo-x/chat",
        "/api/v1/hunts/demo-x/chat",
        "/api/v1/hunts/chat",
    ],
)
def test_demo_allows_chat_posts(path):
    with _app_client(_demo_app_settings()) as client:
        r = client.post(path, json={"message": "hi", "objective": "hi"})
        assert not _is_demo_refusal(r)


# ---------------------------------------------------------------------------
# Canned chat lookup (soc_ai.demo.chat.canned_reply) — pure, never raises.
# ---------------------------------------------------------------------------


def test_canned_chat_lookup():
    from soc_ai.demo.chat import canned_reply

    fixtures = {
        "chats": [
            {
                "target": "investigation",
                "id": "i1",
                "messages": [
                    {"role": "user", "content": "q"},
                    {"role": "assistant", "content": "canned A"},
                ],
            },
        ]
    }
    assert canned_reply(fixtures, "investigation", "i1") == "canned A"
    # unseeded id → generic fallback (non-empty, mentions demo/recorded)
    fb = canned_reply(fixtures, "investigation", "unknown")
    assert fb and ("demo" in fb.lower() or "recorded" in fb.lower())
    # a hunt id when only an investigation chat is authored → fallback (target-scoped)
    assert canned_reply(fixtures, "hunt", "i1") == fb
    # no fixtures at all → still returns the fallback, never raises
    assert canned_reply(None, "hunt", "h1")
    # a null `chats` section must not TypeError — still the fallback
    assert canned_reply({"chats": None}, "investigation", "x") == fb


# ---------------------------------------------------------------------------
# GET /api/v1/demo-status: the open flag endpoint behind the SPA's honesty
# banner ("everything here is a recorded run").
# ---------------------------------------------------------------------------


def test_demo_status_true_in_demo():
    with _app_client(_demo_app_settings()) as client:
        r = client.get("/api/v1/demo-status")
        assert r.status_code == 200
        assert r.json() == {"demo": True}


def test_demo_status_false_outside_demo():
    with _app_client(Settings(**_base_settings_kwargs())) as client:
        r = client.get("/api/v1/demo-status")
        assert r.status_code == 200
        assert r.json() == {"demo": False}


def test_demo_status_open_without_auth():
    """Anonymous GET succeeds with API auth ON — the endpoint lives on
    open_router so the banner renders on any auth config, including pre-login."""
    settings = _demo_app_settings().model_copy(update={"api_auth_required": True})
    with _app_client(settings) as client:
        r = client.get("/api/v1/demo-status")
        assert r.status_code == 200  # notably: not 401
        assert r.json() == {"demo": True}


# ---------------------------------------------------------------------------
# Replay runner (Task 6): the two allowlisted POSTs replay recorded fixtures
# through the LIVE recorder path — same store rows, same SSE/poll surfaces.
# ---------------------------------------------------------------------------

REPLAY_FIXTURE: dict[str, Any] = {
    "version": 1,
    "investigations": [],
    "hunts": [],
    "backtests": [],
    "alerts": [],
    "replays": [
        {
            "alert_es_id": "demo-alert-1",
            "investigation": {
                "rule_name": "ET SCAN Demo Replay",
                "verdict": "false_positive",
                "confidence": 0.91,
                "status": "complete",
            },
            "events": [
                {
                    "kind": "session_start",
                    "sequence": 1,
                    "payload": {"alert_id": "demo-alert-1", "pipeline": "synth_first"},
                },
                {
                    "kind": "enriched_alert_context",
                    "sequence": 2,
                    "payload": {
                        "alert": {
                            "rule_name": "ET SCAN Demo Replay",
                            "source_ip": "203.0.113.7",
                            "destination_ip": "198.51.100.2",
                        }
                    },
                },
                {
                    "kind": "triage_report",
                    "sequence": 3,
                    "payload": {
                        "verdict": "false_positive",
                        "confidence": 0.91,
                        "summary": "Recorded demo replay verdict.",
                        "recommended_actions": [
                            {"action": "acknowledge", "rationale": "Benign scanner traffic."}
                        ],
                    },
                },
                {"kind": "done", "sequence": 4, "payload": {}},
            ],
        }
    ],
}


def _sse_event_kinds(body: str) -> list[str]:
    """Ordered `event:` names from a raw SSE body (same as the tee tests)."""
    return [
        line.split(":", 1)[1].strip() for line in body.splitlines() if line.startswith("event:")
    ]


def _sse_inv_id(body: str) -> str:
    """investigation_id from the leading investigation_created frame (the first
    `data:` line — the created event is always first), parsed as JSON rather
    than string-split so the assertion doesn't depend on dump separators."""
    first_data = next(line for line in body.splitlines() if line.startswith("data:"))
    inv_id: str = json.loads(first_data.split(":", 1)[1])["investigation_id"]
    return inv_id


@contextmanager
def _replay_app(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    *,
    max_step_s: float = 0.01,
) -> Iterator[TestClient]:
    """Demo app whose fixture file carries a replays[] entry; fast test pacing."""
    path = tmp_path / "fixtures.json"
    path.write_text(json.dumps(REPLAY_FIXTURE))
    monkeypatch.setattr("soc_ai.demo.fixtures.DEFAULT_FIXTURES", path)
    monkeypatch.setattr("soc_ai.demo.replay.MAX_STEP_S", max_step_s)
    with _app_client(_demo_app_settings()) as client:
        yield client


def _poll_investigation(client: TestClient, inv_id: str, *, timeout_s: float = 15.0) -> dict:
    """Poll the normal list API (the UI's surface) until the run leaves 'running'."""
    deadline = time.monotonic() + timeout_s
    row: dict | None = None
    while time.monotonic() < deadline:
        rows = client.get("/api/v1/investigations").json()
        row = next((r for r in rows if r["id"] == inv_id), None)
        if row is not None and row["status"] != "running":
            return row
        time.sleep(0.05)
    raise AssertionError(f"investigation {inv_id} never finished; last row: {row}")


def test_demo_investigate_replays_fixture(monkeypatch, tmp_path):
    """POST /investigate in demo streams the RECORDED events over SSE (live
    contract: leading investigation_created, then {session_id,sequence,payload}
    frames) and lands a complete row the normal GET endpoints serve."""
    with _replay_app(monkeypatch, tmp_path) as client:
        with client.stream("POST", "/investigate", json={"alert_id": "demo-alert-1"}) as resp:
            assert resp.status_code == 200
            body = "".join(resp.iter_text())

        kinds = _sse_event_kinds(body)
        assert kinds[0] == "investigation_created"
        assert kinds[1:] == [
            "session_start",
            "enriched_alert_context",
            "triage_report",
            "done",
        ]
        # Recorded payloads stream through the same encoder as live runs.
        assert "Recorded demo replay verdict." in body

        inv_id = _sse_inv_id(body)
        assert inv_id
        rows = client.get("/api/v1/investigations").json()
        row = next(r for r in rows if r["id"] == inv_id)
        assert row["alertId"] == "demo-alert-1"
        assert row["status"] == "complete"
        assert row["verdict"] == "false_positive"
        assert row["name"] == "ET SCAN Demo Replay"
        assert row["host"] == "203.0.113.7"
        assert row["dst"] == "198.51.100.2"


def test_demo_investigate_unknown_alert_mirrors_live_error(monkeypatch, tmp_path):
    """No recording for the alert → the stream mirrors the live pipeline's
    unknown-alert reporting: 200 SSE, session_start, then a prefetch-phase
    error event (same payload keys as orchestrator._error_payload) — NOT a
    crash, NOT a new error shape. Unlike a live unknown-alert run, NO row is
    created (F37): an unrecorded alert_id has nothing to persist, and an
    unauthenticated demo visitor must not be able to flood the DB with one
    permanent row per bogus alert_id."""
    with _replay_app(monkeypatch, tmp_path) as client:
        before = client.get("/api/v1/investigations").json()
        with client.stream("POST", "/investigate", json={"alert_id": "no-such-alert"}) as resp:
            assert resp.status_code == 200
            body = "".join(resp.iter_text())

        kinds = _sse_event_kinds(body)
        assert "investigation_created" not in kinds
        assert kinds[0] == "session_start"
        assert "error" in kinds
        assert '"phase": "prefetch"' in body

        after = client.get("/api/v1/investigations").json()
        assert after == before


def test_demo_investigate_unknown_alert_flood_creates_no_rows(monkeypatch, tmp_path):
    """F37: looping POST /investigate with garbage alert_id values (the demo's
    own allow-listed, unauthenticated write path) must not grow the
    investigations table at all — each unrecorded alert_id streams its error
    and lands nothing."""
    with _replay_app(monkeypatch, tmp_path) as client:
        for i in range(10):
            with client.stream("POST", "/investigate", json={"alert_id": f"garbage-{i}"}) as resp:
                assert resp.status_code == 200
                "".join(resp.iter_text())

        assert client.get("/api/v1/investigations").json() == []


def test_demo_hunt_replays_fixture_in_background(monkeypatch, tmp_path):
    """POST /api/v1/hunt in demo keeps the live contract — returns the new
    investigation id immediately, replays in the background, and the polled
    row ends complete with the recorded verdict fields."""
    with _replay_app(monkeypatch, tmp_path) as client:
        r = client.post("/api/v1/hunt", json={"alert_id": "demo-alert-1"})
        assert r.status_code == 200
        inv_id = r.json()["investigation_id"]

        row = _poll_investigation(client, inv_id)
        assert row["status"] == "complete"
        assert row["verdict"] == "false_positive"
        assert row["name"] == "ET SCAN Demo Replay"
        assert row["host"] == "203.0.113.7"


def test_demo_hunt_unknown_alert_404s_like_live(monkeypatch, tmp_path):
    """No recording → the same 404 shape the live path uses for unknown alerts."""
    with _replay_app(monkeypatch, tmp_path) as client:
        r = client.post("/api/v1/hunt", json={"alert_id": "no-such-alert"})
        assert r.status_code == 404
        assert r.json()["detail"]["reason"] == "alert_not_found"


def test_demo_hunt_second_click_409_while_running_then_new_row(monkeypatch, tmp_path):
    """Second-click behavior: while the replay runs, a duplicate POST gets the
    live 409 hunt_in_progress; after completion a re-click replays into a NEW
    row (live parity) — duplicates are bounded to one RUNNING replay per alert."""
    # 0.4s/step × 3 between-step pauses = a ≥1.2s running window for the 409
    # probe — wide enough not to flake on a loaded CI box.
    with _replay_app(monkeypatch, tmp_path, max_step_s=0.4) as client:
        r1 = client.post("/api/v1/hunt", json={"alert_id": "demo-alert-1"})
        assert r1.status_code == 200
        inv1 = r1.json()["investigation_id"]

        r2 = client.post("/api/v1/hunt", json={"alert_id": "demo-alert-1"})
        assert r2.status_code == 409
        assert r2.json()["detail"]["reason"] == "hunt_in_progress"
        assert r2.json()["detail"]["running_inv_id"] == inv1

        assert _poll_investigation(client, inv1)["status"] == "complete"

        r3 = client.post("/api/v1/hunt", json={"alert_id": "demo-alert-1"})
        assert r3.status_code == 200
        inv3 = r3.json()["investigation_id"]
        assert inv3 != inv1
        assert _poll_investigation(client, inv3)["status"] == "complete"


def test_replay_pacing_math():
    """2 events and 200 events both land within the cap."""
    from soc_ai.demo.replay import MAX_STEP_S, TOTAL_REPLAY_S, step_delay

    assert step_delay(2) == MAX_STEP_S  # short recording: snappy steps
    assert step_delay(200) == pytest.approx(TOTAL_REPLAY_S / 200)
    assert step_delay(200) * 200 <= TOTAL_REPLAY_S  # long recording: capped total
    assert step_delay(0) == MAX_STEP_S  # degenerate: no div-by-zero


def test_find_replay_lookup():
    from soc_ai.demo.replay import find_replay

    data = {"replays": [{"alert_es_id": "a", "events": []}]}
    assert find_replay(data, "a") is data["replays"][0]
    assert find_replay(data, "b") is None
    assert find_replay(None, "a") is None
    assert find_replay({}, "a") is None


async def test_replay_frame_contract_matches_recorded_run(monkeypatch):
    """The SSE frame contract — a leading investigation_created, then
    (kind, {session_id, sequence, payload}) — must stay identical between the
    live runner and its demo twin (persistence can't drift: the recorder is
    shared; the FRAME shape is the drift risk). Runs storeless — the recorder
    is fail-soft, so frames flow without a DB."""
    from types import SimpleNamespace

    from soc_ai.agent.orchestrator import StepEvent
    from soc_ai.api.runner import recorded_run
    from soc_ai.demo.replay import replay_recorded_run

    monkeypatch.setattr("soc_ai.demo.replay.MAX_STEP_S", 0.01)

    def _no_store():
        raise RuntimeError("contract test runs storeless")

    state = SimpleNamespace(db_sessionmaker=_no_store)

    async def live_stream():
        yield StepEvent(kind="session_start", session_id="sid", sequence=1, payload={"a": 1})
        yield StepEvent(kind="done", session_id="sid", sequence=2, payload={})

    live = [
        (name, sorted(data))
        async for name, data in recorded_run(
            state, alert_id="a1", started_by="t", event_stream=live_stream()
        )
    ]
    replay = {
        "alert_es_id": "a1",
        "investigation": {},
        "events": [
            {"kind": "session_start", "sequence": 1, "payload": {"a": 1}},
            {"kind": "done", "sequence": 2, "payload": {}},
        ],
    }
    replayed = [
        (name, sorted(data))
        async for name, data in replay_recorded_run(
            state, alert_id="a1", started_by="t", replay=replay
        )
    ]

    assert live[0][0] == replayed[0][0] == "investigation_created"
    assert live[0][1] == replayed[0][1] == ["investigation_id"]
    assert [k for k, _ in live] == [k for k, _ in replayed]
    frame_keys = ["payload", "sequence", "session_id"]
    assert len(live) > 1
    assert all(keys == frame_keys for _, keys in live[1:])
    assert all(keys == frame_keys for _, keys in replayed[1:])


async def test_replay_client_disconnect_lands_terminal_state(monkeypatch, tmp_path):
    """A visitor navigating away mid-replay cancels the task consuming the
    /investigate SSE stream. The replay's Investigation row MUST land a terminal
    status straight away (status='error', NOT 'running') — not sit 'running'
    until the 30-min reaper. On a PUBLIC demo this disconnect is the common case.

    This drives the real recorder against a scratch DB and cancels the consumer
    partway through the stream, then reads the row back with NO reaper involved.

    Faithful to production: Starlette/FastAPI run request handlers inside an
    anyio cancel scope, which re-delivers the cancellation on every await until
    the scope exits — so a bare cleanup `await recorder.finish(...)` is itself
    cancelled mid-commit (the SQLAlchemy async pool tears the connection down)
    and orphans the row. The fix shields the terminal write so it commits before
    the unwind. (A bare asyncio ``task.cancel()`` does NOT reproduce this: the
    cancellation is consumed at the first suspension point and the cleanup await
    then completes — only the anyio scope keeps it pending.)
    """
    from types import SimpleNamespace

    import anyio
    from soc_ai.demo.replay import replay_recorded_run
    from soc_ai.store import investigations as inv_svc
    from soc_ai.store.db import make_engine, make_sessionmaker, run_migrations

    monkeypatch.setattr("soc_ai.demo.replay.MAX_STEP_S", 0.02)  # snappy pacing for the test

    settings = Settings(**_base_settings_kwargs())  # DB lands under the clean_env tmp cwd
    engine = make_engine(settings)
    await run_migrations(engine)
    maker = make_sessionmaker(engine)
    state = SimpleNamespace(db_sessionmaker=maker)

    replay = REPLAY_FIXTURE["replays"][0]
    holder: dict[str, str] = {}
    seen: list[str] = []

    async def consume(scope: anyio.CancelScope) -> None:
        async for name, data in replay_recorded_run(
            state, alert_id=replay["alert_es_id"], started_by="visitor", replay=replay
        ):
            if name == "investigation_created":
                holder["id"] = data["investigation_id"]
            seen.append(name)
            # Disconnect after a couple of real events have streamed (mid-replay,
            # well before the terminal 'done' event).
            if len(seen) >= 3:
                scope.cancel()

    async with anyio.create_task_group() as tg:
        tg.start_soon(consume, tg.cancel_scope)

    inv_id = holder["id"]
    async with maker() as db:
        got = await inv_svc.get_with_events(db, inv_id)
    await engine.dispose()

    # We really did disconnect partway — the stream never reached its terminal event.
    assert "done" not in seen
    assert got is not None
    inv, _events = got
    # Terminal immediately, no reaper: the disconnect must not orphan the row.
    assert inv.status == "error"


# ---------------------------------------------------------------------------
# Canned chat replies (zero egress): the investigation chat POST resolves to the
# fixture's scripted assistant answer WITHOUT ever building the LLM gateway. A
# successful canned reply IS the no-egress proof — the egress guard raises the
# moment a model/gateway is constructed, so the completed reply could only have
# come from the short-circuit.
# ---------------------------------------------------------------------------

_CANNED_ANSWER = (
    "Recorded demo answer: the rule matched a substring in a benign software-update "
    "payload; the destination is a known vendor endpoint. Recorded verdict: false_positive."
)

_CHAT_INV_ID = "01DEMOCHAT0000000000000INV"

CHAT_FIXTURE: dict[str, Any] = {
    "version": 1,
    "investigations": [
        {
            "id": _CHAT_INV_ID,
            "alert_es_id": "demo-chat-alert",
            "rule_name": "ET SCAN Demo Chat",
            "verdict": "false_positive",
            "confidence": 0.9,
            "rationale": "recorded demo run",
            "summary": "demo",
            "report": {},
            "src_ip": "203.0.113.7",
            "dest_ip": "198.51.100.2",
            "status": "complete",
            "created_at": "2026-07-01T00:00:00Z",
            "finished_at": "2026-07-01T00:05:00Z",
            "events": [{"kind": "session_start", "sequence": 0, "payload": {}}],
        }
    ],
    "hunts": [],
    "backtests": [],
    "alerts": [],
    "replays": [],
    "chats": [
        {
            "target": "investigation",
            "id": _CHAT_INV_ID,
            "messages": [
                {"role": "user", "content": "Why is this a false positive?"},
                {"role": "assistant", "content": _CANNED_ANSWER},
            ],
        }
    ],
}


def _poll_chat_assistant(client: TestClient, inv_id: str, *, timeout_s: float = 15.0) -> dict:
    """Poll the investigation chat thread until the assistant turn lands (!pending)."""
    deadline = time.monotonic() + timeout_s
    thread: dict | None = None
    while time.monotonic() < deadline:
        thread = client.get(f"/api/v1/investigations/{inv_id}/chat").json()
        if not thread["pending"]:
            assistant = next((m for m in thread["messages"] if m["role"] == "assistant"), None)
            if assistant is not None:
                return assistant
        time.sleep(0.05)
    raise AssertionError(f"assistant turn never completed; last thread: {thread}")


def test_demo_investigation_chat_returns_canned_reply(monkeypatch, tmp_path):
    """POST a chat turn on a seeded investigation in demo mode → the assistant row
    lands the fixture's canned answer, with ZERO egress (the short-circuit fires
    before any model/gateway is built; the egress guard would raise otherwise)."""
    path = tmp_path / "fixtures.json"
    path.write_text(json.dumps(CHAT_FIXTURE))
    monkeypatch.setattr("soc_ai.demo.fixtures.DEFAULT_FIXTURES", path)
    with _app_client(_demo_app_settings()) as client:
        r = client.post(
            f"/api/v1/investigations/{_CHAT_INV_ID}/chat",
            json={"message": "Why is this a false positive?"},
        )
        assert r.status_code == 200, r.text
        assistant = _poll_chat_assistant(client, _CHAT_INV_ID)
        assert assistant["text"] == _CANNED_ANSWER


# The hunt-about chat path is STRUCTURALLY DIFFERENT from the investigation one:
# its turn is stored on a HuntEvent.payload dict (finish_chat_assistant mutates
# the payload) rather than a ChatMessage row, so the short-circuit's persistence
# needs its own end-to-end proof — same zero-egress guarantee.
_HUNT_CANNED_ANSWER = (
    "Recorded demo answer: the periodic DNS to the vendor endpoint matched a known "
    "software-update poller on a fixed cadence — not C2. Recorded disposition: benign."
)

_CHAT_HUNT_ID = "01DEMOCHAT000000000000HUNT"

HUNT_CHAT_FIXTURE: dict[str, Any] = {
    "version": 1,
    "investigations": [],
    "hunts": [
        {
            "id": _CHAT_HUNT_ID,
            "objective": "Hunt for DNS beaconing in the last 24h",
            "kind": "chat",
            "status": "complete",
            "narrative": "Periodic DNS explained by a known updater; no beaconing.",
            "report": {"disposition": "benign", "confidence": 0.75},
            "created_at": "2026-07-01T00:00:00Z",
            "finished_at": "2026-07-01T00:07:00Z",
            "events": [{"kind": "hunt_started", "sequence": 0, "payload": {}}],
        }
    ],
    "backtests": [],
    "alerts": [],
    "replays": [],
    "chats": [
        {
            "target": "hunt",
            "id": _CHAT_HUNT_ID,
            "messages": [
                {"role": "user", "content": "Was any of that DNS traffic C2?"},
                {"role": "assistant", "content": _HUNT_CANNED_ANSWER},
            ],
        }
    ],
}


def _poll_hunt_chat_assistant(client: TestClient, hunt_id: str, *, timeout_s: float = 15.0) -> dict:
    """Poll the hunt-about chat thread until the assistant turn lands (!pending)."""
    deadline = time.monotonic() + timeout_s
    thread: dict | None = None
    while time.monotonic() < deadline:
        thread = client.get(f"/api/v1/hunts/{hunt_id}/chat").json()
        if not thread["pending"]:
            assistant = next((m for m in thread["messages"] if m["role"] == "assistant"), None)
            if assistant is not None:
                return assistant
        time.sleep(0.05)
    raise AssertionError(f"hunt assistant turn never completed; last thread: {thread}")


def test_demo_hunt_chat_returns_canned_reply(monkeypatch, tmp_path):
    """POST a follow-up on a seeded hunt in demo mode → the assistant HuntEvent
    lands the fixture's canned answer, ZERO egress. Mirrors the investigation
    e2e test but exercises the distinct HuntEvent.payload persistence path."""
    path = tmp_path / "fixtures.json"
    path.write_text(json.dumps(HUNT_CHAT_FIXTURE))
    monkeypatch.setattr("soc_ai.demo.fixtures.DEFAULT_FIXTURES", path)
    with _app_client(_demo_app_settings()) as client:
        r = client.post(
            f"/api/v1/hunts/{_CHAT_HUNT_ID}/chat",
            json={"message": "Was any of that DNS traffic C2?"},
        )
        assert r.status_code == 200, r.text
        assistant = _poll_hunt_chat_assistant(client, _CHAT_HUNT_ID)
        assert assistant["text"] == _HUNT_CANNED_ANSWER


# ---------------------------------------------------------------------------
# Hunt-start replay (Task 5): POST /api/v1/hunts/chat in demo replays a recorded
# canned hunt through HuntRecorder — a real hunt_id back, an ordinary completed
# hunt the SPA polls, WITH its narrative + report. Zero egress (the recorder
# writes the store only; no model/gateway is built, so the guard never fires).
# ---------------------------------------------------------------------------

_HUNT_REPLAY_NARRATIVE = (
    "Reviewed 41 SSH sessions across HOST_02, HOST_05, HOST_11. All authenticated to "
    "known service accounts; no first-seen host pairs. No lateral movement."
)

# A faithful HuntReport payload (mirrors what run_hunt emits as the hunt_report
# event: report.model_dump — narrative + findings + confidence + the rest). The
# recorder tees this into the new row's report/narrative on finish("complete").
_HUNT_REPLAY_REPORT: dict[str, Any] = {
    "narrative": _HUNT_REPLAY_NARRATIVE,
    "findings": [
        {
            "title": "No SSH lateral movement",
            "detail": "All 41 sessions authenticated to known service accounts.",
            "severity": "info",
            "category": "observation",
            "hosts": ["HOST_02", "HOST_05", "HOST_11"],
            "citations": [],
        }
    ],
    "affected_hosts": ["HOST_02", "HOST_05", "HOST_11"],
    "mitre_techniques": [],
    "recommended_actions": [],
    "confidence": 0.8,
    "charts": [],
}

HUNT_START_FIXTURE: dict[str, Any] = {
    "version": 1,
    "investigations": [],
    "hunts": [
        {
            "id": "01DEMOHUNTSTART00000000001",
            "objective": "Sweep the last 24h for SSH lateral movement between internal hosts",
            "kind": "chat",
            "status": "complete",
            "narrative": _HUNT_REPLAY_NARRATIVE,
            "report": _HUNT_REPLAY_REPORT,
            "created_at": "2026-07-01T00:00:00Z",
            "finished_at": "2026-07-01T00:07:00Z",
            "events": [
                {
                    "kind": "hunt_started",
                    "sequence": 1,
                    "payload": {"objective": "SSH lateral movement sweep"},
                },
                {
                    "kind": "tool_call",
                    "sequence": 2,
                    "payload": {
                        "tool_name": "query_events",
                        "args": {"oql": "event.dataset:zeek.ssh"},
                    },
                },
                {"kind": "tool_result", "sequence": 3, "payload": {"result": {"count": 41}}},
                {"kind": "hunt_report", "sequence": 4, "payload": _HUNT_REPLAY_REPORT},
                {"kind": "done", "sequence": 5, "payload": {"finding_count": 1}},
            ],
        }
    ],
    "backtests": [],
    "alerts": [],
    "replays": [],
    "chats": [],
}


def _poll_hunt(client: TestClient, hunt_id: str, *, timeout_s: float = 15.0) -> dict:
    """Poll GET /hunts/{id} (the Hunt Console detail surface) until it leaves
    'running'."""
    deadline = time.monotonic() + timeout_s
    row: dict | None = None
    while time.monotonic() < deadline:
        resp = client.get(f"/api/v1/hunts/{hunt_id}")
        if resp.status_code == 200:
            row = resp.json()
            if row["status"] != "running":
                return row
        time.sleep(0.05)
    raise AssertionError(f"hunt {hunt_id} never finished; last row: {row}")


def test_demo_hunt_start_replays_canned_hunt(monkeypatch, tmp_path):
    """POST /api/v1/hunts/chat in demo replays the first seeded canned hunt: it
    returns a real hunt_id (not None, not the demo 403), replays in the
    background, and the polled detail ends 'complete' WITH the canned narrative +
    report + timeline — an ordinary completed hunt, not an empty one. Zero egress:
    the egress guard raises the instant a model is built, so a completed replay
    could only have come from the recorder-only short-circuit."""
    path = tmp_path / "fixtures.json"
    path.write_text(json.dumps(HUNT_START_FIXTURE))
    monkeypatch.setattr("soc_ai.demo.fixtures.DEFAULT_FIXTURES", path)
    monkeypatch.setattr("soc_ai.demo.hunt_replay.MAX_STEP_S", 0.01)
    with _app_client(_demo_app_settings()) as client:
        r = client.post("/api/v1/hunts/chat", json={"objective": "hunt for anything suspicious"})
        assert r.status_code == 200, r.text
        assert not _is_demo_refusal(r)
        hunt_id = r.json()["hunt_id"]
        assert hunt_id

        row = _poll_hunt(client, hunt_id)
        assert row["status"] == "complete"
        # The replayed hunt renders fully — narrative + timeline + report content.
        assert row["narrative"] == _HUNT_REPLAY_NARRATIVE
        assert row["timeline"]  # hunt_started / tool_call / hunt_report rendered
        assert row["confidence"] == 0.8
        assert any(f["title"] == "No SSH lateral movement" for f in row["findings"])


def test_hunt_replay_pick_and_pacing():
    """pick_canned_hunt returns the first hunt whose events include a hunt_report
    (skipping eventless AND report-less rows — a report-less replay would land
    'error'); _step_delay caps a long recording's total and never divides by
    zero."""
    from soc_ai.demo.hunt_replay import MAX_STEP_S, TOTAL_REPLAY_S, _step_delay, pick_canned_hunt

    fixtures = {
        "hunts": [
            {"id": "a", "events": []},  # eventless → skip
            {"id": "b", "events": [{"kind": "hunt_started"}]},  # events, NO hunt_report → skip
            {"id": "c", "events": [{"kind": "hunt_started"}, {"kind": "hunt_report"}]},  # → pick
        ]
    }
    # "c" is chosen over "a" (eventless) and "b" (events but no hunt_report).
    assert pick_canned_hunt(fixtures)["id"] == "c"
    # A hunt with events but no hunt_report anywhere is never picked.
    assert pick_canned_hunt({"hunts": [{"id": "b", "events": [{"kind": "tool_call"}]}]}) is None
    assert pick_canned_hunt({"hunts": []}) is None
    assert pick_canned_hunt(None) is None
    assert pick_canned_hunt({"hunts": None}) is None  # null section: no TypeError

    assert _step_delay(2) == MAX_STEP_S  # short recording: snappy
    assert _step_delay(200) == pytest.approx(TOTAL_REPLAY_S / 200)
    assert _step_delay(200) * 200 <= TOTAL_REPLAY_S  # long recording: capped
    assert _step_delay(0) == MAX_STEP_S  # degenerate: no div-by-zero


async def test_hunt_replay_cancel_lands_terminal_state(monkeypatch):
    """App shutdown cancels the demo hunt-replay drain: main.py's lifespan extends
    its worker-drain list with state.demo_replay_tasks and calls task.cancel() on
    each BEFORE db_engine.dispose(). The hunt row MUST land a terminal status
    straight away (status='error', NOT 'running') — the shielded finish() in
    _drain commits the terminal write before the cancellation unwind, so no row is
    orphaned in 'running' until the reaper.

    Mirrors the investigation twin (test_replay_client_disconnect_lands_terminal_state)
    but exercises THIS file's real cancel vector — a plain asyncio.Task.cancel(),
    exactly what main.py does — against a scratch DB, cancelling mid-drain (before
    the trailing hunt_report records), then reading the row back with NO reaper."""
    import asyncio
    import contextlib
    from types import SimpleNamespace

    from soc_ai.demo.hunt_replay import start_background_hunt_replay
    from soc_ai.store import hunts as hunt_svc
    from soc_ai.store.db import make_engine, make_sessionmaker, run_migrations

    # Wide per-step pacing so we can cancel while the drain sleeps between the
    # early events, well before the trailing hunt_report event is recorded.
    monkeypatch.setattr("soc_ai.demo.hunt_replay.MAX_STEP_S", 0.5)

    settings = Settings(**_base_settings_kwargs())  # DB lands under the clean_env tmp cwd
    engine = make_engine(settings)
    await run_migrations(engine)
    maker = make_sessionmaker(engine)
    state = SimpleNamespace(db_sessionmaker=maker)

    hunt = HUNT_START_FIXTURE["hunts"][0]  # SSH hunt: hunt_started ... hunt_report ... done
    hunt_id = await start_background_hunt_replay(state, "objective", "visitor", hunt)
    assert hunt_id is not None

    # The drain registered its task on state.demo_replay_tasks — exactly the set
    # main.py cancels on shutdown.
    assert state.demo_replay_tasks
    task = next(iter(state.demo_replay_tasks))

    # Let the first event (hunt_started) record + flush, then cancel while the
    # drain sleeps before the next step — mid-drain, before hunt_report/finish.
    await asyncio.sleep(0.1)
    task.cancel()
    with contextlib.suppress(asyncio.CancelledError):
        await task

    async with maker() as db:
        got = await hunt_svc.get_with_events(db, hunt_id)
    await engine.dispose()

    assert got is not None
    hunt_row, events = got
    # We really did cancel mid-drain: hunt_started landed, hunt_report never did.
    assert any(e.kind == "hunt_started" for e in events)
    assert all(e.kind != "hunt_report" for e in events)
    # Terminal immediately, no reaper: the shielded finish landed the row 'error'.
    assert hunt_row.status == "error"
