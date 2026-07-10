"""Tests for investigation-history → runbook-draft promotion.

Covers: candidate discovery (min-count floor, pipeline-fallback exclusion,
already-covered-rule exclusion incl. drafts, ordering + dominant verdict);
the distillation service with a ``FunctionModel`` capturing the composed
prompt (history stats, FP-pattern grounding, structured-output mapping,
audit event); the egress ROUND-TRIP when ``analyst_cloud_redaction`` is on
(internal IP labeled on the outbound prompt, restored in the stored draft);
the draft-exclusion guarantee across all retrieval tiers (FTS, legacy
scorer, rule-link boost, semantic); the approve flow (flag flip + embed);
API shapes + auth; and migration 0020's backfill default.

No real gateway or model is ever hit: the analyst model is a pydantic-ai
``FunctionModel`` and the embeddings gateway is patched where needed.
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import datetime
from typing import Any
from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient
from pydantic_ai.messages import (
    ModelMessage,
    ModelRequest,
    ModelResponse,
    ToolCallPart,
    UserPromptPart,
)
from pydantic_ai.models.function import AgentInfo, FunctionModel
from soc_ai.audit.schemas import AuditEvent
from soc_ai.config import Settings
from soc_ai.main import create_app
from soc_ai.rag import runbook_embeddings as rag_svc
from soc_ai.store import chat_memory
from soc_ai.store import investigations as inv_svc
from soc_ai.store import runbooks as runbooks_svc
from soc_ai.store.db import make_engine, make_sessionmaker, run_migrations
from soc_ai.store.models import Runbook, RunbookEmbedding
from soc_ai.webui import runbook_promotion as promo
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker

RULE = "ET INFO Periodic Gateway Heartbeat"
SRC = "10.0.0.1"
DST = "10.0.0.2"

# Patch target: the service imports the builder at module top, so the double
# must land on the promotion module's binding (mirrors test_prior_outcomes).
_BUILD = "soc_ai.webui.runbook_promotion.build_synthesizer_model"


async def _db(settings: Settings) -> tuple[AsyncEngine, async_sessionmaker[AsyncSession]]:
    engine = make_engine(settings)
    await run_migrations(engine)
    return engine, make_sessionmaker(engine)


async def _seed_complete(
    db: AsyncSession,
    *,
    rule_name: str = RULE,
    verdict: str = "false_positive",
    src_ip: str = SRC,
    dest_ip: str = DST,
    rationale: str | None = "expected periodic heartbeat from the gateway",
    fallback: bool = False,
    alert_es_id: str = "seed",
) -> str:
    """One completed, verdict-bearing investigation; optionally a pipeline fallback."""
    inv = await inv_svc.create(
        db,
        alert_es_id=alert_es_id,
        started_by="t",
        rule_name=rule_name,
        src_ip=src_ip,
        dest_ip=dest_ip,
    )
    report = {"resolution": {"provenance": "pipeline_fallback"}} if fallback else None
    await inv_svc.finalize(
        db,
        inv.id,
        status="complete",
        verdict=verdict,
        confidence=0.9,
        rationale=rationale,
        report=report,
    )
    return inv.id


def _user_prompt(messages: list[ModelMessage]) -> str:
    """Extract the composed user prompt from a FunctionModel's request."""
    for msg in messages:
        if isinstance(msg, ModelRequest):
            for part in msg.parts:
                if isinstance(part, UserPromptPart):
                    assert isinstance(part.content, str)
                    return part.content
    raise AssertionError("no UserPromptPart in model request")


def _draft_model(captured: dict[str, Any], args: dict[str, Any] | None = None) -> FunctionModel:
    """A model that records the outbound prompt and returns a structured draft."""
    out = args or {
        "title": "Triage: Periodic Gateway Heartbeat",
        "content": "## When this fires\nGateway heartbeat traffic.",
        "tags": ["heartbeat", "benign"],
        "linked_rules": [],
    }

    def _fn(messages: list[ModelMessage], info: AgentInfo) -> ModelResponse:
        captured["prompt"] = _user_prompt(messages)
        return ModelResponse(parts=[ToolCallPart(tool_name=info.output_tools[0].name, args=out)])

    return FunctionModel(_fn)


# ---------------------------------------------------------------------------
# Candidate discovery
# ---------------------------------------------------------------------------


async def test_promotable_rules_applies_min_count_floor(settings_kratos: Settings) -> None:
    engine, maker = await _db(settings_kratos)
    async with maker() as db:
        for i in range(3):
            await _seed_complete(db, rule_name="RULE A", alert_es_id=f"a{i}")
        for i in range(2):
            await _seed_complete(db, rule_name="RULE B", alert_es_id=f"b{i}")
        rules = await promo.promotable_rules(db)
    assert [r["rule_name"] for r in rules] == ["RULE A"]
    assert rules[0]["investigations"] == 3
    assert rules[0]["dominant_verdict"] == "false_positive"
    await engine.dispose()


async def test_promotable_rules_excludes_pipeline_fallbacks(settings_kratos: Settings) -> None:
    """A fallback row is failure noise — it must not count toward the floor."""
    engine, maker = await _db(settings_kratos)
    async with maker() as db:
        for i in range(2):
            await _seed_complete(db, alert_es_id=f"ok{i}")
        await _seed_complete(db, alert_es_id="fb", fallback=True)
        assert await promo.promotable_rules(db) == []  # 2 real < 3 floor
        await _seed_complete(db, alert_es_id="ok2")
        rules = await promo.promotable_rules(db)
    assert rules[0]["investigations"] == 3  # the fallback never counted
    await engine.dispose()


async def test_promotable_rules_excludes_already_linked_rules(
    settings_kratos: Settings,
) -> None:
    """Any runbook linking the rule — DRAFT included — removes it from the list
    (draft counting is what makes the "Draft it" button idempotent)."""
    engine, maker = await _db(settings_kratos)
    async with maker() as db:
        for i in range(3):
            await _seed_complete(db, rule_name="RULE A", alert_es_id=f"a{i}")
            await _seed_complete(db, rule_name="RULE B", alert_es_id=f"b{i}")
        await runbooks_svc.create(db, title="covered", linked_rules=["RULE A"])
        rules = await promo.promotable_rules(db)
        assert [r["rule_name"] for r in rules] == ["RULE B"]
        await runbooks_svc.create(db, title="drafted", linked_rules=["RULE B"], draft=True)
        assert await promo.promotable_rules(db) == []
    await engine.dispose()


async def test_promotable_rules_orders_by_newest_activity(settings_kratos: Settings) -> None:
    engine, maker = await _db(settings_kratos)
    async with maker() as db:
        # Seed interleaved so ids (the created_at tiebreak) put B's newest last.
        for i in range(3):
            await _seed_complete(db, rule_name="RULE A", alert_es_id=f"a{i}")
        for i in range(3):
            await _seed_complete(db, rule_name="RULE B", alert_es_id=f"b{i}")
        rules = await promo.promotable_rules(db)
    assert [r["rule_name"] for r in rules] == ["RULE B", "RULE A"]
    await engine.dispose()


# ---------------------------------------------------------------------------
# Distillation service
# ---------------------------------------------------------------------------


async def test_draft_runbook_prompt_grounding_and_mapping(settings_kratos: Settings) -> None:
    """The composed prompt carries the history stats, the FP endpoint patterns,
    and the chat snippet; the structured output lands as a draft=True runbook
    with the rule force-linked."""
    engine, maker = await _db(settings_kratos)
    async with maker() as db:
        for i in range(3):
            await _seed_complete(db, alert_es_id=f"s{i}")
        await _seed_complete(db, alert_es_id="tp", verdict="true_positive", src_ip="10.9.9.9")
        # A chat thread mentioning the rule — should surface as a snippet.
        chat_memory.record_message(
            db,
            source="investigation",
            thread_id="01THREAD",
            role="user",
            content=f"we know {SRC}, it is the monitoring box - {RULE} is always benign",
        )
        await db.commit()

        captured: dict[str, Any] = {}
        audit = AsyncMock()
        with patch(_BUILD, return_value=_draft_model(captured)):
            drafted = await promo.draft_runbook_for_rule(
                db, settings_kratos, RULE, created_by="op", audit=audit
            )

    prompt = captured["prompt"]
    # History stats: 3 FP + 1 TP, with the per-investigation digest lines.
    assert "3 false_positive" in prompt
    assert "1 true_positive" in prompt
    assert "expected periodic heartbeat from the gateway" in prompt
    # FP-pattern section fed with the endpoints seen in FP verdicts only.
    assert "FALSE-POSITIVE verdicts" in prompt
    assert f"{SRC} → {DST}" in prompt
    assert "10.9.9.9" not in prompt.split("FALSE-POSITIVE")[1].split("##")[0]
    # Chat snippet fed as context.
    assert "monitoring box" in prompt
    # Required structure is demanded explicitly.
    for heading in (
        "When this fires",
        "What it has meant here",
        "How to triage",
        "Known-benign patterns",
        "Escalate when",
    ):
        assert heading in prompt

    rb = drafted.runbook
    assert rb.draft is True
    assert rb.title == "Triage: Periodic Gateway Heartbeat"
    assert rb.content.startswith("## When this fires")
    assert rb.tags == ["heartbeat", "benign"]
    assert RULE in rb.linked_rules  # forced even though the model returned []
    assert rb.created_by == "op"
    assert drafted.investigations_used == 4

    # Audit: whitelist kind, light payload (rule + counts + id, never content).
    audit.log_kind.assert_awaited_once()
    kwargs = audit.log_kind.await_args.kwargs
    assert kwargs["kind"] == "runbook_promotion"
    assert kwargs["payload"]["rule_name"] == RULE
    assert kwargs["payload"]["investigations"] == 4
    assert kwargs["payload"]["runbook_id"] == rb.id
    assert "content" not in kwargs["payload"]
    # The kind validates against the AuditKind whitelist (silent-drop trap).
    AuditEvent(session_id="s", kind="runbook_promotion", payload={})
    await engine.dispose()


async def test_draft_runbook_no_history_raises(settings_kratos: Settings) -> None:
    engine, maker = await _db(settings_kratos)
    async with maker() as db:
        # Only a fallback row exists — not promotable history.
        await _seed_complete(db, alert_es_id="fb", fallback=True)
        with pytest.raises(promo.NoPromotableHistoryError):
            await promo.draft_runbook_for_rule(db, settings_kratos, RULE)
        # No partial row was written.
        assert list((await db.scalars(select(Runbook))).all()) == []
    await engine.dispose()


async def test_draft_runbook_egress_round_trip(settings_kratos: Settings) -> None:
    """analyst_cloud_redaction on: the outbound prompt carries opaque labels
    (never the internal IP), and the STORED draft carries the real IP back
    (desanitized) with no labels left."""
    marker_ip = "10.66.77.88"  # private ⇒ auto-redacted by the sanitizer
    settings = settings_kratos.model_copy(update={"analyst_cloud_redaction": True})
    engine, maker = await _db(settings)
    async with maker() as db:
        for i in range(3):
            await _seed_complete(
                db,
                alert_es_id=f"s{i}",
                src_ip=marker_ip,
                rationale=f"traffic from {marker_ip} is the vuln scanner",
            )

        captured: dict[str, Any] = {}

        def _fn(messages: list[ModelMessage], info: AgentInfo) -> ModelResponse:
            prompt = _user_prompt(messages)
            captured["prompt"] = prompt
            # Echo every label back — the service must restore ALL of them.
            labels = sorted(set(re.findall(r"\b(?:IP|HOST)_\d+\b", prompt)))
            args = {
                "title": "Triage: heartbeat",
                "content": "Known-benign sources: " + ", ".join(labels),
                "tags": [],
                "linked_rules": [],
            }
            return ModelResponse(
                parts=[ToolCallPart(tool_name=info.output_tools[0].name, args=args)]
            )

        with patch(_BUILD, return_value=FunctionModel(_fn)):
            drafted = await promo.draft_runbook_for_rule(db, settings, RULE)

    prompt = captured["prompt"]
    # Outbound: the internal IP never egressed; a stable label went instead.
    assert marker_ip not in prompt
    assert re.search(r"\bIP_\d+\b", prompt)
    # Stored draft: the real IP is back and no label residue remains.
    content = drafted.runbook.content
    assert marker_ip in content
    assert not re.search(r"\b(?:IP|HOST)_\d+\b", content)
    await engine.dispose()


# ---------------------------------------------------------------------------
# Draft exclusion from retrieval (the "nothing auto-applies" guarantee)
# ---------------------------------------------------------------------------


async def _drop_fts(engine: AsyncEngine) -> None:
    """Simulate an FTS5-less install (triggers first — see test_runbooks_fts)."""
    async with engine.begin() as conn:
        for name in ("runbook_fts_au", "runbook_fts_ad", "runbook_fts_ai"):
            await conn.execute(text(f"DROP TRIGGER IF EXISTS {name}"))
        await conn.execute(text("DROP TABLE IF EXISTS runbook_fts"))


async def _seed_pair(db: AsyncSession) -> tuple[Any, Any]:
    """One published + one DRAFT runbook, both matching rule/keyword/tag."""
    published = await runbooks_svc.create(
        db,
        title="zebra heartbeat triage",
        content="published zebra guidance",
        tags=["zebra"],
        linked_rules=[RULE],
    )
    draft = await runbooks_svc.create(
        db,
        title="zebra heartbeat DRAFT",
        content="draft zebra guidance",
        tags=["zebra"],
        linked_rules=[RULE],
        draft=True,
    )
    return published, draft


async def test_draft_excluded_from_fts_and_rule_link_search(
    settings_kratos: Settings,
) -> None:
    engine, maker = await _db(settings_kratos)
    async with maker() as db:
        published, _draft = await _seed_pair(db)
        # Keyword path (FTS BM25) and rule-link path both see ONLY the published row.
        by_keyword = await runbooks_svc.search(db, "zebra", k=5)
        by_rule = await runbooks_svc.search(db, "", k=5, rule_name=RULE)
    assert [r["id"] for r in by_keyword] == [published.id]
    assert [r["id"] for r in by_rule] == [published.id]
    await engine.dispose()


async def test_draft_excluded_from_legacy_scorer(settings_kratos: Settings) -> None:
    engine, maker = await _db(settings_kratos)
    await _drop_fts(engine)
    async with maker() as db:
        published, _draft = await _seed_pair(db)
        by_keyword = await runbooks_svc.search(db, "zebra", k=5)
        by_rule = await runbooks_svc.search(db, "", k=5, rule_name=RULE)
    assert [r["id"] for r in by_keyword] == [published.id]
    assert [r["id"] for r in by_rule] == [published.id]
    await engine.dispose()


async def test_draft_excluded_from_semantic_search(settings_kratos: Settings) -> None:
    """Even a draft that somehow HAS a vector never comes back semantically."""
    settings = settings_kratos.model_copy(update={"rag_embed_model": "test-embed"})
    engine, maker = await _db(settings)
    async with maker() as db:
        published, draft = await _seed_pair(db)
        fake_embed = AsyncMock(return_value=[[1.0, 0.0, 0.0]])
        with patch("soc_ai.rag.runbook_embeddings.embed_texts", fake_embed):
            # Force-embed BOTH rows (identical vectors ⇒ identical cosine).
            await rag_svc.embed_runbook(db, published, settings=settings)
            await rag_svc.embed_runbook(db, draft, settings=settings)
            hits = await rag_svc.semantic_search(db, "zebra", settings=settings, k=5)
    assert [rb.id for rb, _cos in hits] == [published.id]
    await engine.dispose()


async def test_list_all_still_returns_drafts(settings_kratos: Settings) -> None:
    """The Runbooks page must SHOW drafts — exclusion is retrieval-only."""
    engine, maker = await _db(settings_kratos)
    async with maker() as db:
        published, draft = await _seed_pair(db)
        rows = await runbooks_svc.list_all(db)
    assert {r.id for r in rows} == {published.id, draft.id}
    await engine.dispose()


async def test_reembed_missing_skips_drafts(settings_kratos: Settings) -> None:
    settings = settings_kratos.model_copy(update={"rag_embed_model": "test-embed"})
    engine, maker = await _db(settings)
    async with maker() as db:
        _published, draft = await _seed_pair(db)
        fake_embed = AsyncMock(return_value=[[1.0, 0.0, 0.0]])
        with patch("soc_ai.rag.runbook_embeddings.embed_texts", fake_embed):
            counts = await rag_svc.reembed_missing(db, settings=settings)
        assert counts == {"total": 1, "embedded": 1, "skipped": 0, "failed": 0}
        assert await db.get(RunbookEmbedding, draft.id) is None
    await engine.dispose()


# ---------------------------------------------------------------------------
# API: promotable / promote / approve
# ---------------------------------------------------------------------------


@contextmanager
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


@pytest.fixture
def client(settings_kratos: Settings) -> Iterator[TestClient]:
    with _client(settings_kratos) as c:
        yield c


async def _fake_draft(
    db: AsyncSession,
    _settings: Any,
    rule_name: str,
    *,
    created_by: str = "anonymous",
    audit: Any = None,
) -> promo.DraftRunbook:
    """Route-level service double: lands a REAL draft row through the store
    (so the response serialization + list badging are exercised end-to-end)
    while skipping the model call. Signature mirrors draft_runbook_for_rule."""
    rb = await runbooks_svc.create(
        db,
        title=f"Triage: {rule_name}",
        content="## When this fires\ndistilled",
        tags=["auto"],
        linked_rules=[rule_name],
        created_by=created_by,
        draft=True,
    )
    return promo.DraftRunbook(runbook=rb, investigations_used=3, chat_snippets_used=1)


def test_promote_endpoint_creates_draft_and_shape(client: TestClient) -> None:
    """Through the route: the response is a RunbookOut with draft=true, the row
    shows badged in the list, and normal authoring stays draft=false."""
    with patch("soc_ai.webui.runbook_promotion.draft_runbook_for_rule", _fake_draft):
        resp = client.post("/api/v1/runbooks/promote", json={"rule_name": RULE})
    assert resp.status_code == 200
    body = resp.json()
    assert body["draft"] is True
    assert RULE in body["linked_rules"]
    assert body["title"] == f"Triage: {RULE}"

    listing = client.get("/api/v1/runbooks").json()
    assert any(r["id"] == body["id"] and r["draft"] is True for r in listing)

    authored = client.post("/api/v1/runbooks", json={"title": "manual", "content": "x"}).json()
    assert authored["draft"] is False  # normal authoring is never a draft


def test_promotable_endpoint_shape(client: TestClient) -> None:
    rows = [
        {
            "rule_name": RULE,
            "investigations": 4,
            "false_positive": 3,
            "true_positive": 1,
            "needs_more_info": 0,
            "dominant_verdict": "false_positive",
            "last_activity": datetime(2026, 7, 1, 12, 0, 0),
        }
    ]
    with patch("soc_ai.webui.runbook_promotion.promotable_rules", AsyncMock(return_value=rows)):
        resp = client.get("/api/v1/runbooks/promotable")
    assert resp.status_code == 200
    body = resp.json()
    assert body[0]["rule_name"] == RULE
    assert body[0]["investigations"] == 4
    assert body[0]["dominant_verdict"] == "false_positive"
    assert body[0]["last_activity"].startswith("2026-07-01T12:00:00")


def test_promote_endpoint_failure_mapping(client: TestClient) -> None:
    """no history → 404; blocked egress → 502 count-only; model crash → 502."""
    from soc_ai.agent.egress_guard import EgressResidueError

    target = "soc_ai.webui.runbook_promotion.draft_runbook_for_rule"
    with patch(target, AsyncMock(side_effect=promo.NoPromotableHistoryError(RULE))):
        r = client.post("/api/v1/runbooks/promote", json={"rule_name": RULE})
    assert r.status_code == 404
    assert r.json()["detail"]["reason"] == "no_history"

    with patch(target, AsyncMock(side_effect=EgressResidueError(["10.0.0.1 leaked"]))):
        r = client.post("/api/v1/runbooks/promote", json={"rule_name": RULE})
    assert r.status_code == 502
    detail = r.json()["detail"]
    assert detail["reason"] == "egress_blocked"
    assert detail["leaked_count"] == 1
    assert "10.0.0.1" not in r.text  # the leaked VALUE never reaches the client

    with patch(target, AsyncMock(side_effect=RuntimeError("gateway down"))):
        r = client.post("/api/v1/runbooks/promote", json={"rule_name": RULE})
    assert r.status_code == 502
    assert r.json()["detail"]["reason"] == "draft_failed"


def test_approve_endpoint_publishes_and_embeds(settings_kratos: Settings) -> None:
    settings = settings_kratos.model_copy(update={"rag_embed_model": "test-embed"})
    fake_embed = AsyncMock(return_value=[[1.0, 0.0, 0.0]])
    with (
        patch("soc_ai.rag.runbook_embeddings.embed_texts", fake_embed),
        _client(settings) as client,
    ):
        with patch("soc_ai.webui.runbook_promotion.draft_runbook_for_rule", _fake_draft):
            draft = client.post("/api/v1/runbooks/promote", json={"rule_name": RULE}).json()
        assert draft["draft"] is True
        assert draft["embedded"] is False  # drafts are NOT embedded at creation

        resp = client.post(f"/api/v1/runbooks/{draft['id']}/approve")
        assert resp.status_code == 200
        body = resp.json()
        assert body["draft"] is False
        assert body["embedded"] is True  # embed-on-approve landed

        # 404 on a missing id.
        assert client.post("/api/v1/runbooks/999999/approve").status_code == 404


def test_promotion_endpoints_require_auth(settings_kratos: Settings) -> None:
    """With API auth on and no session, all three endpoints refuse."""
    settings = settings_kratos.model_copy(update={"api_auth_required": True})
    with _client(settings) as client:
        assert client.get("/api/v1/runbooks/promotable").status_code == 401
        assert client.post("/api/v1/runbooks/promote", json={"rule_name": RULE}).status_code == 401
        assert client.post("/api/v1/runbooks/1/approve").status_code == 401


# ---------------------------------------------------------------------------
# Migration 0020: backfill default
# ---------------------------------------------------------------------------


async def test_migration_backfills_existing_rows_as_published(
    settings_kratos: Settings,
) -> None:
    """A runbook that exists when 0020 runs stays retrievable (draft=0)."""
    from alembic import command
    from soc_ai.store.db import _migration_config
    from sqlalchemy import Connection

    def _upgrade_to(connection: Connection, rev: str) -> None:
        cfg = _migration_config()
        cfg.attributes["connection"] = connection
        command.upgrade(cfg, rev)

    engine = make_engine(settings_kratos)
    async with engine.begin() as conn:
        await conn.run_sync(_upgrade_to, "0019")
    async with engine.begin() as conn:
        await conn.execute(
            text(
                "INSERT INTO runbook (title, content, tags, linked_rules, created_by)"
                " VALUES ('pre-existing', 'zebra body', '[]', '[]', 'op')"
            )
        )
    async with engine.begin() as conn:
        await conn.run_sync(_upgrade_to, "head")

    maker = make_sessionmaker(engine)
    async with maker() as db:
        hits = await runbooks_svc.search(db, "zebra", k=5)
    assert [h["title"] for h in hits] == ["pre-existing"]
    await engine.dispose()
