"""Tests for chat-transcript memory (migration 0018 + store + pipeline wiring).

Operator's hard rule under test throughout: past chat transcripts are CONTEXT,
never evidence — the user in a transcript is not always right, so user turns
must surface as labeled, unverified opinion and nothing recalled from a chat
may ground a verdict.

Coverage map:

- migration 0018 — projection table + FTS index/triggers created; backfill
  pulls COMPLETED messages from BOTH sources (``chat_messages`` columns and
  ``hunt_events`` JSON payloads), skipping pending/errored/empty rows;
- write-time dual-write — the four chat write paths land ``chat_memory``
  rows; investigation/hunt deletes cascade to the projection;
- retrieval — BM25 relevance ordering, window/exclude/limit filters,
  MATCH-injection safety, FTS5-missing → ``[]`` fallback, snippet truncation;
- pipeline injection (mirrors ``tests/test_prior_outcomes.py``) — block
  present only when ``memory_enabled`` AND ``memory_include_chat``; per-line
  USER labeling; the ``chat_memory`` timeline event (light payload); fail-soft
  on a store error; the citation gate refusing transcript-grounded citations;
  egress redaction of an internal IP inside a snippet;
- config console — ``memory_include_chat`` visible + settable.

NO real gateway/model is ever called: the synth agent is a pydantic-ai
``TestModel`` stub whose ``run`` is an ``AsyncMock``, so
``fake_agent.run.call_args[0][0]`` IS the composed outbound round-1 prompt
(captured AFTER the sanitize sweep + egress check, exactly what would egress).
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from datetime import timedelta
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi.testclient import TestClient
from pydantic_ai import Agent
from pydantic_ai.models.test import TestModel
from soc_ai.agent.orchestrator import InvestigationContext, investigate
from soc_ai.agent.triage import TriageReport
from soc_ai.config import Settings
from soc_ai.main import create_app
from soc_ai.so_client.elastic import ElasticClient
from soc_ai.so_client.models import SoAlert
from soc_ai.store import chat as chat_svc
from soc_ai.store import chat_memory as mem_svc
from soc_ai.store import hunts as hunt_svc
from soc_ai.store import investigations as inv_svc
from soc_ai.store.auth import utcnow
from soc_ai.store.db import make_engine, make_sessionmaker, run_migrations
from soc_ai.store.models import ChatMemory
from soc_ai.tools.get_alert_context import EnrichedAlertContext
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker

# Same constraints as tests/test_prior_outcomes.py: the rule name must stay out
# of the malware/exploit class AND must not contain words the citation-gate
# tests quote. Its words double as the chat-recall query terms here.
RULE = "ET INFO Periodic Gateway Heartbeat"
SRC = "10.0.0.1"
DST = "10.0.0.2"

# Distinctive marker planted in seeded chat content. Long + unique so the
# block-presence assertions can't false-positive on unrelated prompt text, and
# so the citation-gate test exercises the >=8-char semantic-resolution branch.
CHAT_MARKER = "vulnscan-Qz83xWtR"

BLOCK_HEADER = "## Prior discussion excerpts"

# A chat line an analyst plausibly typed about a PAST alert of this rule —
# carries the query tokens (gateway/heartbeat + src IP) and the marker.
CHAT_TEXT = f"That gateway heartbeat from {SRC} is our vuln scanner — known noise {CHAT_MARKER}."


async def _db(settings: Settings) -> tuple[AsyncEngine, async_sessionmaker[AsyncSession]]:
    engine = make_engine(settings)
    await run_migrations(engine)
    return engine, make_sessionmaker(engine)


async def _drop_fts(engine: AsyncEngine) -> None:
    """Simulate an FTS5-less install / pre-0018 DB: remove the index + triggers.

    Triggers first — with the virtual table gone but a trigger left behind,
    every projection INSERT would error inside the trigger body.
    """
    async with engine.begin() as conn:
        for name in ("chat_memory_fts_au", "chat_memory_fts_ad", "chat_memory_fts_ai"):
            await conn.execute(text(f"DROP TRIGGER IF EXISTS {name}"))
        await conn.execute(text("DROP TABLE IF EXISTS chat_memory_fts"))


async def _seed_snippet(
    maker: async_sessionmaker[AsyncSession],
    content: str,
    *,
    thread_id: str = "thread-a",
    source: str = mem_svc.SOURCE_INVESTIGATION,
    role: str = "user",
) -> None:
    """Seed one projection row directly (retrieval tests need no source tables)."""
    async with maker() as db:
        mem_svc.record_message(db, source=source, thread_id=thread_id, role=role, content=content)
        await db.commit()


async def _all_memory_rows(maker: async_sessionmaker[AsyncSession]) -> list[ChatMemory]:
    async with maker() as db:
        return list((await db.scalars(select(ChatMemory).order_by(ChatMemory.id))).all())


# =====================================================================
# Migration 0018: schema objects + two-source backfill
# =====================================================================


async def test_migration_creates_projection_fts_and_triggers(settings_kratos: Settings) -> None:
    engine, _maker = await _db(settings_kratos)
    async with engine.connect() as conn:
        rows = await conn.execute(text("SELECT type, name FROM sqlite_master"))
        objects = {(t, n) for t, n in rows.all()}
    names = {n for _t, n in objects}
    assert "chat_memory" in names
    assert "chat_memory_fts" in names
    assert "ix_chat_memory_thread_id" in names
    assert {"chat_memory_fts_ai", "chat_memory_fts_ad", "chat_memory_fts_au"} <= {
        n for t, n in objects if t == "trigger"
    }
    await engine.dispose()


async def test_migration_backfills_both_chat_sources(settings_kratos: Settings) -> None:
    """Chats that EXIST when 0018 runs (an upgraded install) are projected +
    indexed by the migration itself — from investigation chat COLUMNS and hunt
    chat JSON payloads alike; pending/errored/empty/non-chat rows are skipped.
    Mirrors the 0017 backfill test's migrate-seed-migrate pattern."""
    from alembic import command
    from soc_ai.store.db import _migration_config
    from sqlalchemy import Connection

    def _upgrade_to(connection: Connection, rev: str) -> None:
        cfg = _migration_config()
        cfg.attributes["connection"] = connection
        command.upgrade(cfg, rev)

    engine = make_engine(settings_kratos)
    # Migrate only to 0017 (pre-projection), seed both sources raw, THEN 0018.
    async with engine.begin() as conn:
        await conn.run_sync(_upgrade_to, "0017")
    async with engine.begin() as conn:
        await conn.execute(
            text(
                "INSERT INTO investigations (id, alert_es_id, status, started_by) "
                "VALUES ('inv-bf-1', 'a1', 'complete', 't')"
            )
        )
        await conn.execute(
            text(
                "INSERT INTO chat_messages (investigation_id, role, content, status) VALUES "
                "('inv-bf-1', 'user', 'that host is the vuln scanner', 'done'), "
                "('inv-bf-1', 'assistant', 'agreed, periodic heartbeat pattern', 'done'), "
                "('inv-bf-1', 'assistant', '', 'pending'), "
                "('inv-bf-1', 'assistant', 'sorry, interrupted', 'error')"
            )
        )
        await conn.execute(
            text(
                "INSERT INTO hunts (id, objective, kind, status, started_by) "
                "VALUES ('hunt-bf-1', 'find beaconing', 'chat', 'complete', 't')"
            )
        )
        await conn.execute(
            text(
                "INSERT INTO hunt_events (hunt_id, sequence, kind, payload) VALUES "
                """('hunt-bf-1', 1, 'chat_user', '{"content": "gateway heartbeat again?", "status": "done"}'), """  # noqa: E501
                """('hunt-bf-1', 2, 'chat_assistant', '{"content": "", "status": "pending"}'), """
                """('hunt-bf-1', 3, 'chat_assistant', '{"content": "yes, benign heartbeat", "status": "done"}'), """  # noqa: E501
                """('hunt-bf-1', 4, 'narrative', '{"text": "not a chat row"}')"""
            )
        )
    async with engine.begin() as conn:
        await conn.run_sync(_upgrade_to, "head")

    maker = make_sessionmaker(engine)
    rows = await _all_memory_rows(maker)
    projected = {(r.source, r.thread_id, r.role, r.content) for r in rows}
    assert projected == {
        ("investigation", "inv-bf-1", "user", "that host is the vuln scanner"),
        ("investigation", "inv-bf-1", "assistant", "agreed, periodic heartbeat pattern"),
        ("hunt", "hunt-bf-1", "user", "gateway heartbeat again?"),
        ("hunt", "hunt-bf-1", "assistant", "yes, benign heartbeat"),
    }
    # …and the migration's FTS backfill makes them retrievable immediately.
    async with maker() as db:
        hits = await mem_svc.relevant_chat_snippets(
            db, query_terms=["heartbeat"], exclude_thread=None, window_days=90, limit=5
        )
    assert {h["thread_id"] for h in hits} == {"inv-bf-1", "hunt-bf-1"}
    await engine.dispose()


# =====================================================================
# Write-time dual-write + delete cascade
# =====================================================================


async def test_investigation_chat_dual_write_and_delete_cascade(
    settings_kratos: Settings,
) -> None:
    """add_user_message projects immediately; a pending assistant row projects
    only when finished DONE (never on error); deleting the investigation
    removes its projection rows."""
    engine, maker = await _db(settings_kratos)
    async with maker() as db:
        inv = await inv_svc.create(db, alert_es_id="a1", started_by="t")
        await chat_svc.add_user_message(db, inv.id, "that host is the vuln scanner")
        pending = await chat_svc.create_pending_assistant(db, inv.id)
        # pending: not knowledge yet — nothing projected for it.
        assert len(await _all_memory_rows(maker)) == 1
        await chat_svc.finish_assistant(db, pending.id, content="agreed, benign")
        errored = await chat_svc.create_pending_assistant(db, inv.id)
        await chat_svc.finish_assistant(db, errored.id, content="oops", status="error")

    rows = await _all_memory_rows(maker)
    assert [(r.source, r.thread_id, r.role, r.content) for r in rows] == [
        ("investigation", inv.id, "user", "that host is the vuln scanner"),
        ("investigation", inv.id, "assistant", "agreed, benign"),
    ]

    async with maker() as db:
        assert await inv_svc.delete(db, inv.id) is True
    assert await _all_memory_rows(maker) == []
    # …and the FTS index followed (delete trigger): retrieval finds nothing.
    async with maker() as db:
        assert (
            await mem_svc.relevant_chat_snippets(
                db, query_terms=["scanner"], exclude_thread=None, window_days=90, limit=5
            )
            == []
        )
    await engine.dispose()


async def test_hunt_chat_dual_write_and_delete_cascade(settings_kratos: Settings) -> None:
    """Same contract on the hunt side, where chat lives in HuntEvent JSON."""
    engine, maker = await _db(settings_kratos)
    async with maker() as db:
        hunt = await hunt_svc.create(db, objective="find beaconing", started_by="t")
        await hunt_svc.add_chat_user_message(db, hunt.id, "gateway heartbeat again?")
        pending = await hunt_svc.create_pending_chat_assistant(db, hunt.id)
        assert len(await _all_memory_rows(maker)) == 1
        await hunt_svc.finish_chat_assistant(db, pending.id, content="yes, benign heartbeat")
        errored = await hunt_svc.create_pending_chat_assistant(db, hunt.id)
        await hunt_svc.finish_chat_assistant(db, errored.id, content="oops", status="error")

    rows = await _all_memory_rows(maker)
    assert [(r.source, r.thread_id, r.role, r.content) for r in rows] == [
        ("hunt", hunt.id, "user", "gateway heartbeat again?"),
        ("hunt", hunt.id, "assistant", "yes, benign heartbeat"),
    ]

    async with maker() as db:
        assert await hunt_svc.delete(db, hunt.id) is True
    assert await _all_memory_rows(maker) == []
    await engine.dispose()


# =====================================================================
# Retrieval: ranking, filters, safety, fallback
# =====================================================================


async def test_retrieval_bm25_relevance_ordering(settings_kratos: Settings) -> None:
    """A message matching more query terms outranks a single-term match, and
    the digest shape is the documented contract."""
    engine, maker = await _db(settings_kratos)
    await _seed_snippet(maker, CHAT_TEXT, thread_id="thread-a")  # heartbeat+gateway+IP
    await _seed_snippet(maker, "an unrelated heartbeat mention", thread_id="thread-b")
    async with maker() as db:
        hits = await mem_svc.relevant_chat_snippets(
            db,
            query_terms=["gateway", "heartbeat", SRC],
            exclude_thread=None,
            window_days=90,
            limit=5,
        )
    assert [h["thread_id"] for h in hits] == ["thread-a", "thread-b"]
    assert hits[0]["score"] > hits[1]["score"]
    assert set(hits[0].keys()) == {"source", "thread_id", "role", "snippet", "created_at", "score"}
    assert hits[0]["role"] == "user"
    assert CHAT_MARKER in hits[0]["snippet"]
    await engine.dispose()


async def test_retrieval_window_excludes_old_chats(settings_kratos: Settings) -> None:
    """A snippet older than the window is filtered out even though FTS ranks it."""
    engine, maker = await _db(settings_kratos)
    await _seed_snippet(maker, CHAT_TEXT)
    async with maker() as db:
        row = (await db.scalars(select(ChatMemory))).one()
        row.created_at = utcnow() - timedelta(days=120)
        await db.commit()
    async with maker() as db:
        assert (
            await mem_svc.relevant_chat_snippets(
                db, query_terms=["heartbeat"], exclude_thread=None, window_days=90, limit=5
            )
            == []
        )
        # widen the window and it comes back — the filter, not the index.
        assert (
            len(
                await mem_svc.relevant_chat_snippets(
                    db, query_terms=["heartbeat"], exclude_thread=None, window_days=365, limit=5
                )
            )
            == 1
        )
    await engine.dispose()


async def test_retrieval_excludes_own_thread(settings_kratos: Settings) -> None:
    """The caller's own thread never echoes back into its own prompt."""
    engine, maker = await _db(settings_kratos)
    await _seed_snippet(maker, CHAT_TEXT, thread_id="thread-self")
    await _seed_snippet(maker, "another heartbeat note", thread_id="thread-other")
    async with maker() as db:
        hits = await mem_svc.relevant_chat_snippets(
            db,
            query_terms=["heartbeat"],
            exclude_thread="thread-self",
            window_days=90,
            limit=5,
        )
    assert [h["thread_id"] for h in hits] == ["thread-other"]
    await engine.dispose()


async def test_retrieval_limit_is_hard_capped_at_five(settings_kratos: Settings) -> None:
    """The per-recall cap holds even if a caller asks for more (each snippet is
    prompt spend); a smaller limit is honored exactly."""
    engine, maker = await _db(settings_kratos)
    for i in range(7):
        await _seed_snippet(maker, f"heartbeat note number {i}", thread_id=f"t-{i}")
    async with maker() as db:
        assert (
            len(
                await mem_svc.relevant_chat_snippets(
                    db, query_terms=["heartbeat"], exclude_thread=None, window_days=90, limit=99
                )
            )
            == 5
        )
        assert (
            len(
                await mem_svc.relevant_chat_snippets(
                    db, query_terms=["heartbeat"], exclude_thread=None, window_days=90, limit=2
                )
            )
            == 2
        )
        assert (
            await mem_svc.relevant_chat_snippets(
                db, query_terms=["heartbeat"], exclude_thread=None, window_days=90, limit=0
            )
            == []
        )
    await engine.dispose()


async def test_retrieval_match_injection_is_safe(settings_kratos: Settings) -> None:
    """Terms stuffed with FTS5 syntax neither raise nor reach the FTS parser —
    they degrade to quoted alphanumeric tokens/phrases."""
    engine, maker = await _db(settings_kratos)
    await _seed_snippet(maker, CHAT_TEXT)
    hostile_terms = [
        'heartbeat" OR "x',
        "NEAR(heartbeat, 2)",
        "((((",
        '"unbalanced',
        "-heartbeat NOT content:x",
        "#!()*",
    ]
    async with maker() as db:
        # Hostile terms alongside a clean one: no error, the clean term still hits.
        hits = await mem_svc.relevant_chat_snippets(
            db,
            query_terms=[*hostile_terms, "heartbeat"],
            exclude_thread=None,
            window_days=90,
            limit=5,
        )
        assert len(hits) == 1
        # Purely symbolic terms → no usable tokens → empty, not an error.
        assert (
            await mem_svc.relevant_chat_snippets(
                db, query_terms=["#!()*", "…"], exclude_thread=None, window_days=90, limit=5
            )
            == []
        )
    await engine.dispose()


def test_fts_match_expr_shapes() -> None:
    """Unit contract of the MATCH builder: multi-token terms become phrases
    (IP selectivity), 1-char standalone tokens drop, everything is quoted."""
    assert mem_svc._fts_match_expr(["10.0.0.1", "heartbeat", "x"]) == '"10 0 0 1" OR "heartbeat"'
    assert mem_svc._fts_match_expr(["#!()*"]) == ""


async def test_retrieval_returns_empty_when_fts_missing(settings_kratos: Settings) -> None:
    """FTS5-less SQLite / pre-0018 DB: retrieval returns [] (no legacy scorer —
    chat memory is advisory) and the session stays usable after the rollback."""
    engine, maker = await _db(settings_kratos)
    await _seed_snippet(maker, CHAT_TEXT)
    await _drop_fts(engine)
    async with maker() as db:
        assert (
            await mem_svc.relevant_chat_snippets(
                db, query_terms=["heartbeat"], exclude_thread=None, window_days=90, limit=5
            )
            == []
        )
        # session usable post-rollback
        assert len((await db.scalars(select(ChatMemory))).all()) == 1
    await engine.dispose()


async def test_snippet_truncates_on_word_boundary(settings_kratos: Settings) -> None:
    """Long chat content is collapsed to one line and cut at a word boundary
    with an ellipsis — a mid-word fragment reads like corruption."""
    engine, maker = await _db(settings_kratos)
    long_content = "heartbeat " + "filler " * 60  # ≫ 240 chars, newline-free words
    await _seed_snippet(maker, long_content)
    async with maker() as db:
        hits = await mem_svc.relevant_chat_snippets(
            db, query_terms=["heartbeat"], exclude_thread=None, window_days=90, limit=5
        )
    snippet = hits[0]["snippet"]
    assert snippet.endswith("…")
    assert len(snippet) <= 241  # 240 + the ellipsis
    assert all(w in ("heartbeat", "filler") for w in snippet[:-1].split())  # no cut words
    await engine.dispose()


# =====================================================================
# Pipeline injection (mirrors tests/test_prior_outcomes.py)
# =====================================================================


def _enriched(alert_id: str = "alert-001") -> EnrichedAlertContext:
    """Enriched stub whose alert carries the (rule, src, dest) the recall keys on."""
    return EnrichedAlertContext(
        alert=SoAlert(
            id=alert_id,
            severity_label="low",
            rule_name=RULE,
            source_ip=SRC,
            destination_ip=DST,
        ),
        pivot_summary={"community_id": 0, "host": 0, "user": 0, "process": 0, "file": 0},
    )


async def _seed_chat_thread(
    maker: async_sessionmaker[AsyncSession], *, content: str = CHAT_TEXT
) -> str:
    """Seed a PAST investigation chat thread carrying institutional knowledge.

    The investigation deliberately uses a DIFFERENT rule name and is never
    finalized, so the E4.2 prior-outcomes recall stays silent — these tests
    measure the chat block in isolation.
    """
    async with maker() as db:
        inv = await inv_svc.create(
            db, alert_es_id="seed-alert", started_by="t", rule_name="Unrelated Seed Rule"
        )
        await chat_svc.add_user_message(db, inv.id, content)
        pending = await chat_svc.create_pending_assistant(db, inv.id)
        await chat_svc.finish_assistant(
            db, pending.id, content="Noted — treating that source as benign scanner traffic."
        )
        return inv.id


def _make_ctx(settings: Settings, maker: Any = None) -> InvestigationContext:
    fake_es = AsyncMock()
    with patch("soc_ai.so_client.elastic.AsyncElasticsearch", return_value=fake_es):
        elastic = ElasticClient(settings)
    return InvestigationContext(
        settings=settings,
        auth=AsyncMock(),
        elastic=elastic,
        db_sessionmaker=maker,
    )


def _report(citations: list[str] | None = None) -> TriageReport:
    return TriageReport(
        verdict="false_positive",
        confidence=0.85,
        summary="Internal heartbeat; expected periodic ICMP.",
        citations=citations if citations is not None else ["alert.severity_label"],
        recommended_actions=[],
        gap_for_investigator=None,
    )


def _strong_benign_candidate() -> Any:
    """Strong benign template match so a zero-tool FP verdict settles round-1."""
    from soc_ai.agent.decision_templates import CandidateVerdict

    return CandidateVerdict(
        verdict="false_positive",
        confidence=0.85,
        cited_evidence=["alert.severity_label"],
        template_id="clean_internal_traffic",
        rationale="internal scanner",
    )


async def _drive(ctx: InvestigationContext, report: TriageReport) -> tuple[list[Any], Any]:
    """Run investigate() end-to-end with a stubbed synth agent.

    Returns ``(events, fake_agent)`` — ``fake_agent.run.call_args[0][0]`` is the
    composed outbound round-1 user message (post-sanitize, post-egress-check).
    """
    fake_agent = Agent(
        model=TestModel(call_tools=[], custom_output_args=report),
        system_prompt="stub",
        output_type=TriageReport,
    )
    fake_agent.run = AsyncMock(return_value=MagicMock(output=report))

    async def _stub_enriched(aid: str, **_kw: Any) -> Any:
        return _enriched(aid)

    with (
        patch(
            "soc_ai.tools.get_alert_context.get_enriched_alert_context",
            side_effect=_stub_enriched,
        ),
        patch(
            "soc_ai.agent.orchestrator.build_synthesizer_model",
            return_value=TestModel(call_tools=[], custom_output_args=report),
        ),
        patch(
            "soc_ai.agent.orchestrator.build_synth_first_agent",
            return_value=fake_agent,
        ),
        patch(
            "soc_ai.agent.decision_templates.match_decision_template",
            return_value=_strong_benign_candidate(),
        ),
    ):
        events = [ev async for ev in investigate("alert-001", ctx=ctx)]
    return events, fake_agent


@pytest.mark.asyncio
async def test_chat_block_injected_when_enabled_with_relevant_chats(
    settings_kratos: Settings,
) -> None:
    """Memory + include_chat on with a relevant seeded chat ⇒ the round-1 prompt
    carries the framed block (USER lines visibly labeled) and a light
    ``chat_memory`` event lands on the timeline."""
    settings_kratos.investigate_when_unsure = False
    settings_kratos.memory_enabled = True
    assert settings_kratos.memory_include_chat is True  # the shipped default
    engine, maker = await _db(settings_kratos)
    thread_id = await _seed_chat_thread(maker)
    ctx = _make_ctx(settings_kratos, maker)

    events, fake_agent = await _drive(ctx, _report())

    msg = fake_agent.run.call_args[0][0]
    assert BLOCK_HEADER in msg
    assert "CONTEXT ONLY" in msg and "NOT evidence" in msg
    assert "may be wrong" in msg  # the user-is-not-always-right framing
    assert CHAT_MARKER in msg  # the snippet made it into the prompt
    # Every USER excerpt is labeled ON ITS LINE, not just in the header.
    assert "· USER]" in msg
    # No priors were seeded (different rule) — the chat block stands alone.
    assert "## Prior outcomes" not in msg

    chat_ev = next(e for e in events if e.kind == "chat_memory")
    assert chat_ev.payload["count"] >= 1
    assert chat_ev.payload["window_days"] == settings_kratos.memory_window_days
    assert {
        "source": "investigation",
        "thread_id": thread_id,
        "role": "user",
    } in chat_ev.payload["items"]
    # Light payload guarantee: snippet text lives in the prompt, never the event.
    assert CHAT_MARKER not in json.dumps(chat_ev.payload)

    assert any(e.kind == "triage_report" for e in events)
    await engine.dispose()


@pytest.mark.asyncio
async def test_chat_block_absent_when_memory_disabled(settings_kratos: Settings) -> None:
    """memory_enabled=False (the shipped default) suppresses chat recall even
    though memory_include_chat defaults True — it is a sub-switch, not a
    stand-alone feature."""
    settings_kratos.investigate_when_unsure = False
    assert settings_kratos.memory_enabled is False
    assert settings_kratos.memory_include_chat is True
    engine, maker = await _db(settings_kratos)
    await _seed_chat_thread(maker)
    ctx = _make_ctx(settings_kratos, maker)

    events, fake_agent = await _drive(ctx, _report())

    msg = fake_agent.run.call_args[0][0]
    assert BLOCK_HEADER not in msg
    assert CHAT_MARKER not in msg
    assert not any(e.kind == "chat_memory" for e in events)
    await engine.dispose()


@pytest.mark.asyncio
async def test_chat_block_absent_when_include_chat_off(settings_kratos: Settings) -> None:
    """memory_enabled=True but memory_include_chat=False ⇒ prior-outcome memory
    machinery may run, chat recall must not."""
    settings_kratos.investigate_when_unsure = False
    settings_kratos.memory_enabled = True
    settings_kratos.memory_include_chat = False
    engine, maker = await _db(settings_kratos)
    await _seed_chat_thread(maker)
    ctx = _make_ctx(settings_kratos, maker)

    events, fake_agent = await _drive(ctx, _report())

    msg = fake_agent.run.call_args[0][0]
    assert BLOCK_HEADER not in msg
    assert CHAT_MARKER not in msg
    assert not any(e.kind == "chat_memory" for e in events)
    await engine.dispose()


@pytest.mark.asyncio
async def test_chat_memory_store_error_is_fail_soft(settings_kratos: Settings) -> None:
    """A store error during chat recall logs + skips the block; the
    investigation still completes with a verdict (memory must never kill a run)."""
    settings_kratos.investigate_when_unsure = False
    settings_kratos.memory_enabled = True
    engine, maker = await _db(settings_kratos)
    await _seed_chat_thread(maker)
    ctx = _make_ctx(settings_kratos, maker)

    with patch(
        "soc_ai.store.chat_memory.relevant_chat_snippets",
        AsyncMock(side_effect=RuntimeError("db exploded")),
    ):
        events, fake_agent = await _drive(ctx, _report())

    assert BLOCK_HEADER not in fake_agent.run.call_args[0][0]
    assert not any(e.kind == "chat_memory" for e in events)
    report_ev = next(e for e in events if e.kind == "triage_report")
    assert report_ev.payload["verdict"] == "false_positive"
    assert events[-1].kind == "done"
    await engine.dispose()


# =====================================================================
# Egress guard: snippets ride the sanitize sweep + fail-closed check
# =====================================================================


@pytest.mark.asyncio
async def test_chat_snippet_redacted_on_cloud_analyst_path(settings_kratos: Settings) -> None:
    """With analyst_cloud_redaction + fail-closed ON, an internal IP inside a
    past chat message is redacted in the captured outbound message — proving
    the block is composed BEFORE the final sanitize sweep and ``_guard_egress``.
    Fail-closed makes this loud: had the IP survived, the model would never
    have been called (egress_blocked) and this test fails."""
    settings_kratos.investigate_when_unsure = False
    settings_kratos.memory_enabled = True
    settings_kratos.analyst_cloud_redaction = True
    settings_kratos.analyst_redaction_fail_closed = True
    engine, maker = await _db(settings_kratos)
    leak_ip = "10.99.88.77"
    await _seed_chat_thread(
        maker,
        content=f"The heartbeat beacons to {leak_ip} — that box is our vuln scanner, ignore it.",
    )
    ctx = _make_ctx(settings_kratos, maker)

    events, fake_agent = await _drive(ctx, _report())

    assert fake_agent.run.called, "the model call must proceed (nothing leaked)"
    assert not any(e.kind == "egress_blocked" for e in events)
    msg = fake_agent.run.call_args[0][0]
    # The block is present (its non-identifier prose survives)…
    assert BLOCK_HEADER in msg
    assert "vuln scanner" in msg
    # …but the chat's internal IP was redacted to an opaque label.
    assert leak_ip not in msg
    await engine.dispose()


# =====================================================================
# Citation gate: transcripts are prompt context, never resolvable evidence
# =====================================================================


def test_chat_snippet_citation_does_not_resolve() -> None:
    """A citation quoting past-chat text has nothing to resolve against — the
    evidence bundle is the enriched context + tool history, and transcripts are
    deliberately NOT materialized into it. Unit-level proof on the exact
    resolver the pipeline uses."""
    from soc_ai.agent.gates import _resolve_citations

    # NB: phrased to dodge the lenient `_CITE_ID_RE` (no word boundary — a word
    # ENDING in "id", like "said", right before the marker would classify the
    # whole citation as a model-trusted strict id and vacuously resolve it).
    citation = f"prior discussion: operator noted {CHAT_MARKER} as benign"
    res = _resolve_citations([citation], _enriched(), [], messages=None)
    assert res["counts"]["valid"] == 0
    assert res["counts"]["unresolved"] == 1
    assert res["coverage_ratio"] == 0.0


@pytest.mark.asyncio
async def test_report_citing_only_chat_text_fails_citation_gate(
    settings_kratos: Settings,
) -> None:
    """End-to-end gate check: with a chat block injected, a report whose ONLY
    citations quote it resolves zero citations — an operator's chat opinion
    can never become citable grounding for the verdict."""
    settings_kratos.investigate_when_unsure = False
    settings_kratos.memory_enabled = True
    engine, maker = await _db(settings_kratos)
    await _seed_chat_thread(maker)
    ctx = _make_ctx(settings_kratos, maker)

    events, fake_agent = await _drive(
        ctx, _report(citations=[f"operator noted {CHAT_MARKER} in a prior discussion"])
    )

    # The block WAS in the prompt (the citation is quoting something real)…
    assert CHAT_MARKER in fake_agent.run.call_args[0][0]
    # …yet it resolves to nothing: the gate holds.
    cit_ev = next(e for e in events if e.kind == "citation_validation")
    assert cit_ev.payload["counts"]["valid"] == 0
    assert cit_ev.payload["coverage_ratio"] == 0.0
    await engine.dispose()


# =====================================================================
# Config console wiring
# =====================================================================


def _client(settings: Settings) -> Iterator[TestClient]:
    fake_es = AsyncMock()
    fake_auth = AsyncMock()
    with (
        patch("soc_ai.so_client.elastic.AsyncElasticsearch", return_value=fake_es),
        patch("soc_ai.main.make_auth", return_value=fake_auth),
        patch("soc_ai.main.get_settings", return_value=settings),
    ):
        app = create_app()
        with TestClient(app) as client:
            yield client


def test_memory_include_chat_visible_and_settable_via_config(settings_kratos: Settings) -> None:
    """The sub-switch lives in the Memory section, is hot, and round-trips.

    (The full Memory key-set assertion lives in tests/test_prior_outcomes.py.)
    """
    for client in _client(settings_kratos):
        groups = {g["title"]: g["items"] for g in client.get("/api/v1/config").json()["groups"]}
        by_key = {item["key"]: item for item in groups["Memory"]}
        assert by_key["memory_include_chat"]["value"] is True  # shipped default

        resp = client.post(
            "/api/v1/config/setting", json={"key": "memory_include_chat", "value": "false"}
        )
        assert resp.status_code == 200
        assert resp.json()["restart_required"] is False  # hot, like its siblings

        groups = {g["title"]: g["items"] for g in client.get("/api/v1/config").json()["groups"]}
        by_key = {item["key"]: item for item in groups["Memory"]}
        assert by_key["memory_include_chat"]["value"] is False
        assert by_key["memory_include_chat"]["source"] == "db"
