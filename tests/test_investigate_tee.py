"""Tests for InvestigationRecorder tee — /investigate persists all callers.

The fake ``investigate`` generator uses the REAL alert_context payload shape:
``{"alert": {"rule_name": "...", ...}, ...}`` (AlertContext.model_dump()).
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator, Iterator
from typing import Any
from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient
from pydantic import SecretStr
from soc_ai.agent.orchestrator import StepEvent
from soc_ai.config import Settings
from soc_ai.main import create_app
from soc_ai.store import investigations as inv_svc
from soc_ai.store.db import make_engine, make_sessionmaker, run_migrations

ADMIN_PW = "test-tee-pw"

REPORT = {
    "verdict": "false_positive",
    "confidence": 0.85,
    "summary": "Benign ICMP echo between gateway and Mac. Nothing else.",
    "citations": ["x7KpQ2"],
    "recommended_actions": [
        {
            "tool_name": "ack_alert",
            "tool_args": {"alert_id": "x7KpQ2"},
            "rationale": "Routine gateway monitoring traffic.",
        }
    ],
}


def _read_investigation(settings: Settings, inv_id: str) -> dict[str, Any]:
    """Sync helper: open a second engine against the same SQLite file and read back
    the stored investigation + event kinds.  Pattern mirrors test_api_auth._mint_token.
    """

    async def _go() -> dict[str, Any]:
        engine = make_engine(settings)
        await run_migrations(engine)
        maker = make_sessionmaker(engine)
        async with maker() as db:
            got = await inv_svc.get_with_events(db, inv_id)
        await engine.dispose()
        assert got is not None, f"investigation {inv_id} not found in DB"
        inv, events = got
        return {
            "status": inv.status,
            "verdict": inv.verdict,
            "rationale": inv.rationale,
            "alert_es_id": inv.alert_es_id,
            "rule_name": inv.rule_name,
            "started_by": inv.started_by,
            "src_ip": inv.src_ip,
            "dest_ip": inv.dest_ip,
            "event_kinds": [e.kind for e in events],
        }

    return asyncio.run(_go())


@pytest.fixture
def tee_settings(settings_kratos: Settings) -> Settings:
    return settings_kratos.model_copy(update={"bootstrap_admin_password": SecretStr(ADMIN_PW)})


@pytest.fixture
def tee_client(tee_settings: Settings) -> Iterator[TestClient]:
    fake_es = AsyncMock()
    fake_auth = AsyncMock()

    async def fake_investigate(
        alert_id: str,
        *,
        ctx: Any,
        agent: Any = None,
        investigator: Any = None,
        synthesizer: Any = None,
        session_id: str | None = None,
    ) -> AsyncIterator[StepEvent]:
        sid = session_id or "fake-tee-sid"
        # The live synth-first path emits enriched_alert_context (EnrichedAlertContext
        # subclasses AlertContext: same {"alert": {"rule_name": ...}} dump shape); the
        # recorder must capture rule_name from it.
        yield StepEvent(
            kind="session_start",
            session_id=sid,
            sequence=1,
            payload={"alert_id": alert_id},
        )
        yield StepEvent(
            kind="enriched_alert_context",
            session_id=sid,
            sequence=2,
            payload={
                "alert": {
                    "rule_name": "ET MALWARE BPFDoor Magic Packet (ICMP)",
                    "id": alert_id,
                    "timestamp": "2026-06-12T06:41:00Z",
                    "source_ip": "10.0.0.41",
                    "destination_ip": "10.0.0.1",
                },
                "community_id_events": [],
                "host_events": [],
                "user_events": [],
                "process_events": [],
                "file_events": [],
                "pivot_summary": {},
                "prefetch_gaps": {},
            },
        )
        yield StepEvent(
            kind="triage_report",
            session_id=sid,
            sequence=3,
            payload=REPORT,
        )
        yield StepEvent(
            kind="done",
            session_id=sid,
            sequence=4,
            payload={"recommended_count": 1},
        )

    with (
        patch("soc_ai.so_client.elastic.AsyncElasticsearch", return_value=fake_es),
        patch("soc_ai.main.make_auth", return_value=fake_auth),
        patch("soc_ai.main.get_settings", return_value=tee_settings),
        patch("soc_ai.api.routes.investigate", fake_investigate),
    ):
        app = create_app()
        with TestClient(app) as client:
            # Log in so the session cookie is set — identify_caller will see "admin".
            client.post(
                "/api/v1/login",
                json={"username": "admin", "password": ADMIN_PW},
            )
            # Cookie-authenticated writes now pass the CSRF Origin guard on the
            # legacy router too; send the app's own origin like the real SPA.
            client.headers["Origin"] = "http://testserver"
            yield client


@pytest.fixture
def crash_client(tee_settings: Settings) -> Iterator[TestClient]:
    """Client where fake_investigate raises after the first event."""
    fake_es = AsyncMock()
    fake_auth = AsyncMock()

    async def crash_investigate(
        alert_id: str,
        *,
        ctx: Any,
        agent: Any = None,
        investigator: Any = None,
        synthesizer: Any = None,
        session_id: str | None = None,
    ) -> AsyncIterator[StepEvent]:
        sid = session_id or "fake-crash-sid"
        yield StepEvent(
            kind="session_start",
            session_id=sid,
            sequence=1,
            payload={"alert_id": alert_id},
        )
        raise RuntimeError("boom — simulated stream crash")

    with (
        patch("soc_ai.so_client.elastic.AsyncElasticsearch", return_value=fake_es),
        patch("soc_ai.main.make_auth", return_value=fake_auth),
        patch("soc_ai.main.get_settings", return_value=tee_settings),
        patch("soc_ai.api.routes.investigate", crash_investigate),
    ):
        app = create_app()
        with TestClient(app) as client:
            yield client


def test_tee_persists_completed_investigation(
    tee_client: TestClient, tee_settings: Settings
) -> None:
    with tee_client.stream("POST", "/investigate", json={"alert_id": "es-123"}) as resp:
        assert resp.status_code == 200
        body = "".join(chunk for chunk in resp.iter_text())

    # The stream announces the investigation id as its first event.
    assert "investigation_created" in body
    inv_id = body.split('"investigation_id": "')[1].split('"')[0]
    assert inv_id  # non-empty ULID

    stored = _read_investigation(tee_settings, inv_id)
    assert stored["status"] == "complete"
    assert stored["verdict"] == "false_positive"
    assert stored["rationale"] == "Routine gateway monitoring traffic."
    assert stored["alert_es_id"] == "es-123"
    assert stored["rule_name"]  # captured from alert_context.alert.rule_name
    assert stored["src_ip"] == "10.0.0.41"
    assert stored["dest_ip"] == "10.0.0.1"
    assert stored["event_kinds"][:2] == ["session_start", "enriched_alert_context"]
    assert "triage_report" in stored["event_kinds"]


def test_tee_marks_error_on_stream_crash(crash_client: TestClient, tee_settings: Settings) -> None:
    """A generator that raises mid-stream must: still yield the error SSE event
    (existing behavior) AND store status == 'error'."""
    with crash_client.stream("POST", "/investigate", json={"alert_id": "es-crash"}) as resp:
        assert resp.status_code == 200
        body = "".join(chunk for chunk in resp.iter_text())

    # Existing behavior: error SSE event must be present.
    assert "error" in body

    # New behavior: investigation row must exist and be marked error.
    assert "investigation_created" in body
    inv_id = body.split('"investigation_id": "')[1].split('"')[0]

    stored = _read_investigation(tee_settings, inv_id)
    assert stored["status"] == "error"


def test_tee_route_seeds_rule_name_when_stream_crashes_before_context(
    crash_client: TestClient, tee_settings: Settings
) -> None:
    """The /investigate route resolves the rule name up front and seeds the row, so
    a stream that crashes BEFORE emitting any alert_context event is still named —
    the userscript path no longer produces a nameless 'Alert <id>…' row."""
    with (
        patch(
            "soc_ai.api.routes.resolve_alert_for_hunt",
            AsyncMock(return_value=(True, "ET SCAN Seeded By Route")),
        ),
        crash_client.stream("POST", "/investigate", json={"alert_id": "es-crash-named"}) as resp,
    ):
        body = "".join(chunk for chunk in resp.iter_text())

    inv_id = body.split('"investigation_id": "')[1].split('"')[0]
    stored = _read_investigation(tee_settings, inv_id)
    assert stored["status"] == "error"  # crashed before a verdict
    assert stored["rule_name"] == "ET SCAN Seeded By Route"  # …but still named


def test_tee_started_by_session_user(tee_client: TestClient, tee_settings: Settings) -> None:
    """When the caller is logged in via session cookie, started_by must be their username."""
    with tee_client.stream("POST", "/investigate", json={"alert_id": "es-auth"}) as resp:
        body = "".join(chunk for chunk in resp.iter_text())

    inv_id = body.split('"investigation_id": "')[1].split('"')[0]
    stored = _read_investigation(tee_settings, inv_id)
    assert stored["started_by"] == "admin"


def _parse_sse_event_kinds(body: str) -> list[str]:
    """Extract the ordered list of SSE event: lines from a raw SSE body."""
    kinds = []
    for line in body.splitlines():
        if line.startswith("event:"):
            kinds.append(line.split(":", 1)[1].strip())
    return kinds


def test_investigation_created_is_first_sse_event(
    tee_client: TestClient,
) -> None:
    """investigation_created must be the FIRST SSE event in the stream."""
    with tee_client.stream("POST", "/investigate", json={"alert_id": "es-order"}) as resp:
        body = "".join(chunk for chunk in resp.iter_text())

    kinds = _parse_sse_event_kinds(body)
    assert kinds[0] == "investigation_created"
    # Subsequent events from the generator must still be present.
    assert "session_start" in kinds
    assert "triage_report" in kinds
    assert "done" in kinds


def test_tee_complete_without_report_stores_error(tee_settings: Settings) -> None:
    """A stream that finishes without a triage_report must store status='error'."""
    fake_es = AsyncMock()
    fake_auth = AsyncMock()

    async def no_report_investigate(
        alert_id: str,
        *,
        ctx: Any,
        agent: Any = None,
        investigator: Any = None,
        synthesizer: Any = None,
        session_id: str | None = None,
    ) -> AsyncIterator[StepEvent]:
        sid = session_id or "fake-noreport-sid"
        yield StepEvent(
            kind="session_start",
            session_id=sid,
            sequence=1,
            payload={"alert_id": alert_id},
        )
        yield StepEvent(
            kind="done",
            session_id=sid,
            sequence=2,
            payload={"recommended_count": 0},
        )

    with (
        patch("soc_ai.so_client.elastic.AsyncElasticsearch", return_value=fake_es),
        patch("soc_ai.main.make_auth", return_value=fake_auth),
        patch("soc_ai.main.get_settings", return_value=tee_settings),
        patch("soc_ai.api.routes.investigate", no_report_investigate),
    ):
        app = create_app()
        with (
            TestClient(app) as client,
            client.stream("POST", "/investigate", json={"alert_id": "es-noreport"}) as resp,
        ):
            body = "".join(chunk for chunk in resp.iter_text())

    inv_id = body.split('"investigation_id": "')[1].split('"')[0]
    stored = _read_investigation(tee_settings, inv_id)
    assert stored["status"] == "error"


def test_broken_store_does_not_break_stream(tee_client: TestClient) -> None:
    """A broken store must degrade to an unpersisted run — stream still delivers events."""
    with (
        patch("soc_ai.api.recorder.inv_svc.create", side_effect=RuntimeError("db gone")),
        tee_client.stream("POST", "/investigate", json={"alert_id": "es-x"}) as resp,
    ):
        assert resp.status_code == 200
        body = "".join(resp.iter_text())
    assert '"investigation_id": null' in body
    assert "triage_report" in body  # stream still delivered the goods


@pytest.mark.asyncio
async def test_seeded_rule_name_survives_run_with_no_alert_context(
    settings_kratos: Settings,
) -> None:
    """THE FIX: a recorder seeded with a rule_name names the row at creation, so a
    run that reaches a terminal state BEFORE emitting any alert_context event
    (e.g. an ES prefetch failure) is still named — never the 'Alert <id>…'
    fallback. This is the exact regression the user reported."""
    from soc_ai.api.recorder import InvestigationRecorder

    engine = make_engine(settings_kratos)
    await run_migrations(engine)
    maker = make_sessionmaker(engine)

    recorder = InvestigationRecorder(
        maker, alert_id="es-seed", started_by="t", rule_name="ET SCAN Seeded Rule"
    )
    inv_id = await recorder.start()
    assert inv_id is not None

    # No alert_context is ever recorded — the run dies straight to a terminal error.
    await recorder.finish("error")

    async with maker() as db:
        got = await inv_svc.get_with_events(db, inv_id)
    await engine.dispose()

    assert got is not None
    inv, _events = got
    assert inv.rule_name == "ET SCAN Seeded Rule"  # named at birth, not NULL
    assert inv.status == "error"


@pytest.mark.asyncio
async def test_unseeded_run_falls_back_to_event_dataset(settings_kratos: Settings) -> None:
    """An unseeded run (selected-id auto-triage) backfills from the stream. When the
    detection has no rule.name (Zeek notice etc.) the recorder falls back to
    event.dataset so the row still gets a meaningful label instead of NULL."""
    from soc_ai.api.recorder import InvestigationRecorder

    engine = make_engine(settings_kratos)
    await run_migrations(engine)
    maker = make_sessionmaker(engine)

    recorder = InvestigationRecorder(maker, alert_id="es-notice", started_by="t", rule_name="")
    inv_id = await recorder.start()
    assert inv_id is not None

    # alert_context with NO rule.name but an event_dataset present.
    await recorder.record(
        "alert_context", 1, {"alert": {"rule_name": None, "event_dataset": "zeek.notice"}}
    )
    await recorder.record("triage_report", 2, REPORT)
    await recorder.finish("complete")

    async with maker() as db:
        got = await inv_svc.get_with_events(db, inv_id)
    await engine.dispose()

    assert got is not None
    inv, _events = got
    assert inv.rule_name == "zeek.notice"  # dataset fallback, not NULL


@pytest.mark.asyncio
async def test_finish_is_idempotent(settings_kratos: Settings) -> None:
    """Calling finish() twice must not change the stored status from the first call."""
    from soc_ai.api.recorder import InvestigationRecorder

    engine = make_engine(settings_kratos)
    await run_migrations(engine)
    maker = make_sessionmaker(engine)

    recorder = InvestigationRecorder(
        maker,
        alert_id="es-idem",
        started_by="test",
    )
    await recorder.start()
    assert recorder.investigation_id is not None

    await recorder.record("triage_report", 1, REPORT)
    await recorder.finish("complete")
    # Second call with a different status — must be a no-op.
    await recorder.finish("error")

    async with maker() as db:
        got = await inv_svc.get_with_events(db, recorder.investigation_id)
    await engine.dispose()

    assert got is not None
    inv, _events = got
    assert inv.status == "complete"
