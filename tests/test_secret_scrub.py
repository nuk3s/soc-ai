"""The secret scrub masks credential values in model-written text before store and export.

Dogfood 2026-10-01 P1: an NMI report quoted "<service> password: <value>" from
telemetry in its rationale, and every console user could read it.
"""

from __future__ import annotations

import asyncio
import json
from collections.abc import Iterator
from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient
from soc_ai.config import Settings
from soc_ai.secret_scrub import REDACTED, scrub_secrets, scrub_value
from soc_ai.store import chat as chat_svc
from soc_ai.store import general_chat as general_chat_svc
from soc_ai.store import hunts as hunt_svc
from soc_ai.store import investigations as inv_svc
from soc_ai.store.db import make_engine, make_sessionmaker, run_migrations
from soc_ai.store.models import Investigation, InvestigationEvent
from sqlalchemy import select

SECRET = "Tr0ub4dor&3x"


@pytest.mark.parametrize(
    "text",
    [
        # The prod shape: a service name, then "password:" with a space.
        f"The request shows webui-svc password: {SECRET} in the body.",
        # Inside a quoted command line.
        f'process.command_line: "mysql.exe --user=root --password={SECRET} -h db.example.test"',
        # Inside a JSON snippet.
        json.dumps({"user": "alice", "password": SECRET, "host": "web01.example.test"}),
        # Inside JSON that sits escaped in a JSON string.
        json.dumps(json.dumps({"password": SECRET})),
        # YAML and env-file shapes, with a prefixed key name.
        f"db_password: {SECRET}\nDB_PASSWORD={SECRET}",
        # A long flag with a space before the value.
        f"curl --token {SECRET} https://api.example.test/",
        f"api_key='{SECRET}' apikey={SECRET} client_secret={SECRET}",
        f"https://alice:{SECRET}@api.example.test/path",
        "Authorization: Basic YWxpY2U6VHIwdWI0ZG9yJjN4",
        "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.Tr0ub4dor3xPayload.sig",
        "aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    ],
)
def test_the_value_is_masked_and_the_key_stays(text: str) -> None:
    out = scrub_secrets(text)
    assert SECRET not in out
    assert "YWxpY2U6VHIwdWI0ZG9yJjN4" not in out
    assert "Tr0ub4dor3xPayload" not in out
    assert "wJalrXUtnFEMI" not in out
    assert REDACTED in out


def test_key_names_usernames_and_hostnames_survive() -> None:
    out = scrub_secrets(
        f'process.command_line: "mysql.exe --user=root --password={SECRET} -h db.example.test"'
    )
    assert "--password=" in out
    assert "--user=root" in out
    assert "db.example.test" in out
    url = scrub_secrets(f"https://alice:{SECRET}@api.example.test/path")
    assert url == f"https://alice:{REDACTED}@api.example.test/path"
    js = json.loads(scrub_secrets(json.dumps({"user": "alice", "password": SECRET})))
    assert js == {"user": "alice", "password": REDACTED}


def test_aws_access_key_id_is_masked() -> None:
    assert scrub_secrets("key AKIAABCDEFGHIJKLMNOP seen") == f"key {REDACTED} seen"


@pytest.mark.parametrize(
    "benign",
    [
        "The password policy requires 12 characters.",
        "Failed password for root from 192.0.2.4 port 22 ssh2.",
        "Passwords were not observed. The token count is low.",
        "input_tokens: 1234, tokens: 5",
        "The Bearer token was refused.",
        "Basic authentication failed for user alice on web01.example.test.",
        "The field user.password is present in the document.",
        f"Already scrubbed: password: {REDACTED}",
    ],
)
def test_benign_prose_is_unchanged(benign: str) -> None:
    assert scrub_secrets(benign) == benign


def test_scrub_value_walks_nested_structures_and_keeps_keys() -> None:
    report = {
        "summary": f"The host sent password={SECRET}.",
        "open_questions": [f"Is token: {SECRET} still valid?"],
        "findings": [{"text": f"secret: {SECRET}", "password": "n/a"}],
        "confidence": 0.5,
    }
    out = scrub_value(report)
    assert SECRET not in json.dumps(out)
    assert set(out) == set(report)
    assert out["confidence"] == 0.5
    assert out["findings"][0]["password"] == "n/a"


# ── store path ────────────────────────────────────────────────────────────────


async def _maker(settings: Settings):  # type: ignore[no-untyped-def]
    engine = make_engine(settings)
    await run_migrations(engine)
    return engine, make_sessionmaker(engine)


async def test_finalize_scrubs_rationale_summary_report_and_report_event(
    settings_kratos: Settings,
) -> None:
    engine, maker = await _maker(settings_kratos)
    leak = f"webui-svc password: {SECRET}"
    report = {
        "verdict": "needs_more_info",
        "confidence": 0.4,
        "summary": f"The request carries {leak}.",
        "open_questions": [f"Who owns the account behind {leak}?"],
        "recommended_actions": [{"tool_name": "ack_alert", "rationale": leak}],
    }
    async with maker() as db:
        inv = await inv_svc.create(db, alert_es_id="doc-secret", started_by="t")
        await inv_svc.append_events(
            db,
            inv.id,
            [
                {"sequence": 1, "kind": "triage_report", "payload": report},
                {"sequence": 2, "kind": "tool_call", "payload": {"raw": leak}},
            ],
        )
        await inv_svc.finalize(
            db,
            inv.id,
            status="complete",
            verdict="needs_more_info",
            confidence=0.4,
            rationale=leak,
            summary=report["summary"],
            report=report,
        )
    async with maker() as db:
        row = await db.get(Investigation, inv.id)
        assert row is not None
        stored = json.dumps([row.rationale, row.summary, row.report])
        assert SECRET not in stored
        assert "webui-svc password: [redacted]" in (row.rationale or "")
        events = (
            (
                await db.execute(
                    select(InvestigationEvent).where(InvestigationEvent.investigation_id == inv.id)
                )
            )
            .scalars()
            .all()
        )
        by_kind = {e.kind: e.payload for e in events}
        assert SECRET not in json.dumps(by_kind["triage_report"])
        # A tool result is evidence and stays verbatim in the store.
        assert by_kind["tool_call"]["raw"] == leak
    await engine.dispose()


async def test_resolve_scrubs_the_override_rationale(settings_kratos: Settings) -> None:
    engine, maker = await _maker(settings_kratos)
    async with maker() as db:
        inv = await inv_svc.create(db, alert_es_id="doc-resolve", started_by="t")
        await inv_svc.finalize(db, inv.id, status="complete", verdict="needs_more_info")
        await inv_svc.resolve(
            db,
            inv.id,
            verdict="true_positive",
            confidence=0.8,
            rationale=f"Analyst saw pwd={SECRET} in the log.",
            recommended_actions=None,
            resolved_by="analyst",
            resolved_via="manual",
        )
        row = await db.get(Investigation, inv.id)
        assert row is not None
        assert SECRET not in (row.rationale or "")
    await engine.dispose()


async def test_chat_answers_are_scrubbed_before_store(settings_kratos: Settings) -> None:
    engine, maker = await _maker(settings_kratos)
    answer = f'The config shows "password": "{SECRET}" for the service.'
    async with maker() as db:
        inv = await inv_svc.create(db, alert_es_id="doc-chat", started_by="t")
        msg = await chat_svc.create_pending_assistant(db, inv.id)
        await chat_svc.finish_assistant(db, msg.id, content=answer)
        rows = await chat_svc.list_messages(db, inv.id)
        assert all(SECRET not in (m.content or "") for m in rows)

        gmsg = await general_chat_svc.create_pending_assistant(db, "thread-1")
        await general_chat_svc.finish_assistant(db, gmsg.id, content=answer)
        grows = await general_chat_svc.list_messages(db, "thread-1")
        assert all(SECRET not in (m.content or "") for m in grows)

        hunt = await hunt_svc.create(db, objective="find the thing", started_by="t")
        hev = await hunt_svc.create_pending_chat_assistant(db, hunt.id)
        await hunt_svc.finish_chat_assistant(db, hev.id, content=answer)
        hrows = await hunt_svc.list_chat_messages(db, hunt.id)
        assert all(SECRET not in json.dumps(e.payload) for e in hrows)
    await engine.dispose()


async def test_hunt_finalize_scrubs_narrative_and_findings(settings_kratos: Settings) -> None:
    engine, maker = await _maker(settings_kratos)
    async with maker() as db:
        hunt = await hunt_svc.create(db, objective="find the thing", started_by="t")
        await hunt_svc.finalize(
            db,
            hunt.id,
            status="complete",
            narrative=f"The share used secret={SECRET}.",
            report={"findings": [{"title": "Cleartext", "detail": f"token: {SECRET}"}]},
        )
        got = await hunt_svc.get_with_events(db, hunt.id)
        assert got is not None
        row, _events = got
        assert SECRET not in json.dumps([row.narrative, row.report])
    await engine.dispose()


# ── export and read paths ────────────────────────────────────────────────────


@pytest.fixture
def client(settings_kratos: Settings) -> Iterator[TestClient]:
    from soc_ai.main import create_app

    with (
        patch("soc_ai.so_client.elastic.AsyncElasticsearch", return_value=AsyncMock()),
        patch("soc_ai.main.make_auth", return_value=AsyncMock()),
        patch("soc_ai.main.get_settings", return_value=settings_kratos),
    ):
        app = create_app()
        with TestClient(app) as c:
            yield c


def test_export_scrubs_a_row_stored_before_the_scrub(client: TestClient) -> None:
    """The negative control sits on the path the store scrub misses: a legacy row."""
    import hashlib

    leak = f"webui-svc password: {SECRET}"

    async def _seed() -> str:
        async with client.app.state.db_sessionmaker() as db:  # type: ignore[attr-defined]
            inv = Investigation(
                id="01LEGACYSECRET0000000000000",
                alert_es_id="doc-legacy",
                started_by="t",
                status="complete",
                verdict="needs_more_info",
                rationale=leak,
                summary=leak,
                report={"summary": leak, "open_questions": [leak]},
            )
            db.add(inv)
            db.add(
                InvestigationEvent(
                    investigation_id=inv.id,
                    sequence=1,
                    kind="tool_call",
                    payload={"raw": f"--password={SECRET}"},
                )
            )
            await db.commit()
            return inv.id

    inv_id = asyncio.run(_seed())
    resp = client.get(f"/api/v1/investigations/{inv_id}/export")
    assert resp.status_code == 200
    assert SECRET not in resp.text
    rec = resp.json()
    # The checksum covers the scrubbed body, so the record still verifies.
    body = {k: v for k, v in rec.items() if k != "integrity"}
    canonical = json.dumps(body, sort_keys=True, separators=(",", ":"), default=str)
    assert hashlib.sha256(canonical.encode()).hexdigest() == rec["integrity"]["hash"]

    with patch("soc_ai.api.webui._timeline._alert_currently_acked", AsyncMock(return_value=False)):
        detail = client.get(f"/api/v1/investigations/{inv_id}")
    assert detail.status_code == 200
    d = detail.json()
    assert SECRET not in json.dumps([d["rationale"], d["summary"], d["openQuestions"]])
