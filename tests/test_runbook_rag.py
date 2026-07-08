"""Tests for the opt-in runbook semantic tier (E4.1): gateway embeddings,
write-time sync, the admin re-embed endpoint, cosine ordering, stale-model
skips, the hybrid merge in ``search()``, and rerank (incl. fail-soft).

NO real gateway is ever hit: every httpx call in soc_ai.rag.runbook_embeddings
is routed through an ``httpx.MockTransport`` (same pattern as
tests/test_web_search.py). The fake ``/v1/embeddings`` maps marker words to
axes of a tiny 3-dim space, so cosine outcomes are exact and deterministic:
``alpha``/``zebra`` → axis 0, ``beta``/``quokka`` → axis 1, ``gamma`` → axis 2;
text with no marker embeds to the zero vector (cosine 0 → never a semantic hit).
"""

from __future__ import annotations

import asyncio
import json
from collections.abc import Iterator
from typing import Any
from unittest.mock import AsyncMock, patch

import httpx
import pytest
from fastapi.testclient import TestClient
from soc_ai.config import Settings
from soc_ai.main import create_app
from soc_ai.rag import runbook_embeddings as rag_svc
from soc_ai.store import runbooks as runbooks_svc
from soc_ai.store.db import make_engine, make_sessionmaker, run_migrations
from soc_ai.store.models import RunbookEmbedding
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker

_REAL = httpx.AsyncClient

_AXES = {"alpha": 0, "zebra": 0, "beta": 1, "quokka": 1, "gamma": 2}


def _fake_vec(text: str) -> list[float]:
    """Deterministic 3-dim embedding: one axis per marker word (see module doc)."""
    vec = [0.0, 0.0, 0.0]
    lowered = text.lower()
    for marker, axis in _AXES.items():
        if marker in lowered:
            vec[axis] += 1.0
    return vec


def _gateway_handler(
    *,
    embed_status: int = 200,
    rerank_status: int = 200,
    rerank_score: Any = None,
) -> Any:
    """Build a MockTransport handler covering /v1/embeddings and /rerank.

    ``rerank_score(doc: str) -> float`` scores each document by CONTENT (never
    by position — candidate order is an implementation detail).
    """

    def handler(req: httpx.Request) -> httpx.Response:
        path = req.url.path
        if path.endswith("/v1/embeddings"):
            if embed_status != 200:
                return httpx.Response(embed_status, json={"error": "boom"})
            body = json.loads(req.content)
            data = [{"index": i, "embedding": _fake_vec(t)} for i, t in enumerate(body["input"])]
            return httpx.Response(200, json={"data": data, "model": body["model"]})
        if path.endswith("/rerank"):
            if rerank_status != 200:
                return httpx.Response(rerank_status, json={"error": "boom"})
            body = json.loads(req.content)
            score = rerank_score or (lambda _doc: 0.5)
            results = [
                {"index": i, "relevance_score": score(doc)}
                for i, doc in enumerate(body["documents"])
            ]
            return httpx.Response(200, json={"results": results})
        return httpx.Response(404, json={"error": f"unexpected path {path}"})

    return handler


def _patch_gateway(handler: Any) -> Any:
    """Route every AsyncClient the rag module builds through the fake transport."""
    transport = httpx.MockTransport(handler)

    def _factory(*a: Any, **k: Any) -> httpx.AsyncClient:
        k["transport"] = transport
        return _REAL(*a, **k)

    return patch("soc_ai.rag.runbook_embeddings.httpx.AsyncClient", _factory)


def _rag_settings(settings: Settings, **over: Any) -> Settings:
    base: dict[str, Any] = {"rag_embed_model": "test-embed"}
    base.update(over)
    return settings.model_copy(update=base)


async def _db(settings: Settings) -> tuple[AsyncEngine, async_sessionmaker[AsyncSession]]:
    engine = make_engine(settings)
    await run_migrations(engine)
    return engine, make_sessionmaker(engine)


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


async def _embedding_rows(settings: Settings) -> list[RunbookEmbedding]:
    """Read the runbook_embedding rows straight from the store file."""
    from sqlalchemy import select

    engine = make_engine(settings)
    maker = make_sessionmaker(engine)
    async with maker() as db:
        rows = list((await db.scalars(select(RunbookEmbedding))).all())
    await engine.dispose()
    return rows


# ---------------------------------------------------------------------------
# Write-time sync: create/update embed fail-SOFT
# ---------------------------------------------------------------------------


def test_embed_on_create_and_update(settings_kratos: Settings) -> None:
    settings = _rag_settings(settings_kratos)
    with _patch_gateway(_gateway_handler()):
        for client in _client(settings):
            created = client.post(
                "/api/v1/runbooks", json={"title": "Alpha triage", "content": "alpha steps"}
            ).json()
            rows = asyncio.run(_embedding_rows(settings))
            assert len(rows) == 1
            assert rows[0].runbook_id == created["id"]
            assert rows[0].model == "test-embed"
            assert rows[0].dim == 3
            assert rag_svc.bytes_to_vector(rows[0].vector) == [1.0, 0.0, 0.0]

            # update re-embeds with the new text
            client.put(f"/api/v1/runbooks/{created['id']}", json={"content": "beta steps"})
            rows = asyncio.run(_embedding_rows(settings))
            assert rag_svc.bytes_to_vector(rows[0].vector) == [1.0, 1.0, 0.0]  # title + body


def test_embed_on_write_is_fail_soft(settings_kratos: Settings) -> None:
    """A down gateway must never fail a runbook save — 200, row saved, just no
    embedding until the next write or a re-embed."""
    settings = _rag_settings(settings_kratos)
    with _patch_gateway(_gateway_handler(embed_status=500)):
        for client in _client(settings):
            resp = client.post("/api/v1/runbooks", json={"title": "Alpha triage"})
            assert resp.status_code == 200
            assert client.get("/api/v1/runbooks").json()[0]["title"] == "Alpha triage"
            assert asyncio.run(_embedding_rows(settings)) == []


def test_no_gateway_call_when_tier_disabled(settings_kratos: Settings) -> None:
    """rag_embed_model unset (the default) ⇒ zero gateway I/O on writes."""
    calls = {"n": 0}

    def handler(req: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        return httpx.Response(200, json={})

    with _patch_gateway(handler):
        for client in _client(settings_kratos):
            assert client.post("/api/v1/runbooks", json={"title": "Alpha"}).status_code == 200
    assert calls["n"] == 0


# ---------------------------------------------------------------------------
# Admin re-embed endpoint: counts + the disabled guard
# ---------------------------------------------------------------------------


def test_reembed_endpoint_counts_and_idempotency(settings_kratos: Settings) -> None:
    settings = _rag_settings(settings_kratos)
    # Author two runbooks while the gateway is DOWN → rows exist, vectors don't.
    with _patch_gateway(_gateway_handler(embed_status=500)):
        for client in _client(settings):
            client.post("/api/v1/runbooks", json={"title": "Alpha triage"})
            client.post("/api/v1/runbooks", json={"title": "Beta triage"})
            # re-embed against the still-down gateway: honest failure counts
            body = client.post("/api/v1/config/rag/reembed").json()
            assert body == {"ok": False, "total": 2, "embedded": 0, "skipped": 0, "failed": 2}
    # Gateway back → the same pass embeds both; a second pass skips both.
    with _patch_gateway(_gateway_handler()):
        for client in _client(settings):
            body = client.post("/api/v1/config/rag/reembed").json()
            assert body == {"ok": True, "total": 2, "embedded": 2, "skipped": 0, "failed": 0}
            body = client.post("/api/v1/config/rag/reembed").json()
            assert body == {"ok": True, "total": 2, "embedded": 0, "skipped": 2, "failed": 0}


def test_reembed_refreshes_stale_model_rows(settings_kratos: Settings) -> None:
    """Switching rag_embed_model marks every existing vector stale — the next
    re-embed rewrites them all under the new model id."""
    with _patch_gateway(_gateway_handler()):
        for client in _client(_rag_settings(settings_kratos)):
            client.post("/api/v1/runbooks", json={"title": "Alpha triage"})
        for client in _client(_rag_settings(settings_kratos, rag_embed_model="new-embed")):
            body = client.post("/api/v1/config/rag/reembed").json()
            assert body["embedded"] == 1
            assert body["skipped"] == 0
            rows = asyncio.run(_embedding_rows(_rag_settings(settings_kratos)))
            assert rows[0].model == "new-embed"


def test_reembed_requires_configured_model(settings_kratos: Settings) -> None:
    for client in _client(settings_kratos):  # rag_embed_model unset
        resp = client.post("/api/v1/config/rag/reembed")
        assert resp.status_code == 400
        assert resp.json()["detail"]["reason"] == "rag_disabled"


# ---------------------------------------------------------------------------
# semantic_search: cosine ordering + stale-model skip
# ---------------------------------------------------------------------------


async def test_semantic_search_orders_by_cosine(settings_kratos: Settings) -> None:
    settings = _rag_settings(settings_kratos)
    engine, maker = await _db(settings)
    async with maker() as db:
        pure = await runbooks_svc.create(db, title="Zebra runbook", content="only that topic")
        mixed = await runbooks_svc.create(db, title="Zebra and quokka", content="two topics")
        with _patch_gateway(_gateway_handler()):
            await rag_svc.embed_runbook(db, pure, settings=settings)
            await rag_svc.embed_runbook(db, mixed, settings=settings)
            # query on axis 0: pure=[1,0,0] → cos 1.0; mixed=[1,1,0] → cos ≈ .707
            hits = await rag_svc.semantic_search(db, "alpha", settings=settings, k=5)
    assert [rb.id for rb, _cos in hits] == [pure.id, mixed.id]
    assert hits[0][1] > hits[1][1] > 0.0
    await engine.dispose()


async def test_semantic_search_skips_stale_model_rows(settings_kratos: Settings) -> None:
    settings = _rag_settings(settings_kratos)
    engine, maker = await _db(settings)
    async with maker() as db:
        rb = await runbooks_svc.create(db, title="Zebra runbook")
        with _patch_gateway(_gateway_handler()):
            await rag_svc.embed_runbook(db, rb, settings=settings)
            # same rows, different configured model → vector space mismatch → no hits
            stale = _rag_settings(settings_kratos, rag_embed_model="other-model")
            assert await rag_svc.semantic_search(db, "alpha", settings=stale, k=5) == []
    await engine.dispose()


# ---------------------------------------------------------------------------
# Hybrid merge + rerank inside search()
# ---------------------------------------------------------------------------


async def test_hybrid_merge_unions_semantic_hits(settings_kratos: Settings) -> None:
    """A runbook with ZERO keyword overlap joins the results via its embedding,
    ranked by the weighted merge (semantic 5*cos beats a small BM25 score)."""
    settings = _rag_settings(settings_kratos)
    engine, maker = await _db(settings)
    async with maker() as db:
        keyword_hit = await runbooks_svc.create(
            db, title="Beacon triage", content="beacon periodicity"
        )
        semantic_hit = await runbooks_svc.create(
            db, title="Zebra callbacks", content="periodic zebra reviews"
        )
        with _patch_gateway(_gateway_handler()):
            await rag_svc.embed_runbook(db, semantic_hit, settings=settings)
            # "alpha beacon": FTS matches only keyword_hit (token "beacon");
            # the query embeds to axis 0 → cos(semantic_hit)=1.0, so it joins.
            results = await runbooks_svc.search(db, "alpha beacon", k=5, settings=settings)
    ids = [r["id"] for r in results]
    assert set(ids) == {keyword_hit.id, semantic_hit.id}
    assert ids[0] == semantic_hit.id  # 5.0 semantic weight > the tiny BM25 score
    await engine.dispose()


async def test_semantic_tier_is_fail_soft_in_search(settings_kratos: Settings) -> None:
    """Gateway down mid-search → keyword results still come back, no raise."""
    settings = _rag_settings(settings_kratos)
    engine, maker = await _db(settings)
    async with maker() as db:
        rb = await runbooks_svc.create(db, title="Beacon triage", content="beacon")
        # an embedded row exists, but the query embedding will fail
        with _patch_gateway(_gateway_handler()):
            await rag_svc.embed_runbook(db, rb, settings=settings)
        with _patch_gateway(_gateway_handler(embed_status=503)):
            results = await runbooks_svc.search(db, "beacon", k=5, settings=settings)
    assert [r["id"] for r in results] == [rb.id]
    await engine.dispose()


async def test_rerank_orders_candidates_and_rule_link_still_wins(
    settings_kratos: Settings,
) -> None:
    settings = settings_kratos.model_copy(update={"rag_rerank_model": "test-rerank"})
    engine, maker = await _db(settings)
    async with maker() as db:
        plain = await runbooks_svc.create(db, title="Beacon notes", content="beacon beacon")
        loved = await runbooks_svc.create(db, title="Beacon loris guide", content="beacon")
        linked = await runbooks_svc.create(
            db, title="Rule guidance", content="beacon", linked_rules=["ET MALWARE Beacon"]
        )
        # the reranker adores "loris" documents and shrugs at everything else
        handler = _gateway_handler(rerank_score=lambda doc: 0.95 if "loris" in doc else 0.05)
        with _patch_gateway(handler):
            results = await runbooks_svc.search(
                db, "beacon", k=5, rule_name="ET MALWARE Beacon", settings=settings
            )
    # rule-link boost dominates the rerank; below it, rerank owns the order
    assert [r["id"] for r in results] == [linked.id, loved.id, plain.id]
    await engine.dispose()


async def test_rerank_is_fail_soft(settings_kratos: Settings) -> None:
    """A rerank failure keeps the merged (BM25) order — never an error."""
    settings = settings_kratos.model_copy(update={"rag_rerank_model": "test-rerank"})
    engine, maker = await _db(settings)
    async with maker() as db:
        title_hit = await runbooks_svc.create(db, title="Beacon triage", content="x")
        content_hit = await runbooks_svc.create(db, title="Notes", content="about beacon")
        with _patch_gateway(_gateway_handler(rerank_status=500)):
            results = await runbooks_svc.search(db, "beacon", k=5, settings=settings)
    assert [r["id"] for r in results] == [title_hit.id, content_hit.id]  # BM25 order stands
    await engine.dispose()


# ---------------------------------------------------------------------------
# Config console wiring: keys visible + settable
# ---------------------------------------------------------------------------


def test_rag_settings_visible_and_settable_via_config(settings_kratos: Settings) -> None:
    for client in _client(settings_kratos):
        groups = {g["title"]: g["items"] for g in client.get("/api/v1/config").json()["groups"]}
        assert "Retrieval (RAG)" in groups
        keys = {item["key"] for item in groups["Retrieval (RAG)"]}
        assert keys == {"rag_embed_model", "rag_rerank_model"}

        # both are hot-apply string settings
        resp = client.post(
            "/api/v1/config/setting", json={"key": "rag_embed_model", "value": "qwen3-embed"}
        )
        assert resp.status_code == 200
        assert resp.json()["restart_required"] is False
        groups = {g["title"]: g["items"] for g in client.get("/api/v1/config").json()["groups"]}
        by_key = {item["key"]: item for item in groups["Retrieval (RAG)"]}
        assert by_key["rag_embed_model"]["value"] == "qwen3-embed"
        assert by_key["rag_embed_model"]["source"] == "db"


@pytest.mark.asyncio
async def test_vector_bytes_roundtrip() -> None:
    vec = [0.25, -1.5, 3.0, 0.0]
    assert rag_svc.bytes_to_vector(rag_svc.vector_to_bytes(vec)) == vec
    assert rag_svc.cosine([1.0, 0.0], [1.0, 0.0]) == pytest.approx(1.0)
    assert rag_svc.cosine([1.0, 0.0], [0.0, 1.0]) == pytest.approx(0.0)
    assert rag_svc.cosine([0.0, 0.0], [1.0, 1.0]) == 0.0  # degenerate → 0, not NaN
