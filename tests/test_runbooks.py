"""Tests for operator runbooks: the store CRUD, the embedding-free search
ranker (rule-link > tag > keyword), the ``lookup_runbook`` tool wiring, the
migration, and the GET/POST/PUT/DELETE runbooks endpoints."""

from __future__ import annotations

from collections.abc import Iterator
from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient
from soc_ai.config import Settings
from soc_ai.main import create_app
from soc_ai.store import runbooks as runbooks_svc
from soc_ai.store.db import make_engine, make_sessionmaker, run_migrations
from soc_ai.tools.lookup_runbook import lookup_runbook
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker


async def _db(settings: Settings) -> tuple[AsyncEngine, async_sessionmaker[AsyncSession]]:
    engine = make_engine(settings)
    await run_migrations(engine)
    return engine, make_sessionmaker(engine)


# ---------------------------------------------------------------------------
# Migration: the new table is created by run_migrations (mirror 0009 test)
# ---------------------------------------------------------------------------


async def test_migration_creates_runbook_table(settings_kratos: Settings) -> None:
    from sqlalchemy import inspect

    engine = make_engine(settings_kratos)
    await run_migrations(engine)
    async with engine.connect() as conn:
        tables = set(await conn.run_sync(lambda sc: inspect(sc).get_table_names()))
    assert "runbook" in tables
    await engine.dispose()


# ---------------------------------------------------------------------------
# Store CRUD
# ---------------------------------------------------------------------------


async def test_create_and_list(settings_kratos: Settings) -> None:
    engine, maker = await _db(settings_kratos)
    async with maker() as db:
        row = await runbooks_svc.create(
            db,
            title="Beaconing triage",
            content="Confirm periodicity in conn logs, then check the dest reputation.",
            tags=["beacon", "c2"],
            linked_rules=["ET MALWARE Cobalt Strike Beacon"],
            created_by="alice",
        )
        assert row.id is not None
        assert row.title == "Beaconing triage"
        assert row.tags == ["beacon", "c2"]
        assert row.linked_rules == ["ET MALWARE Cobalt Strike Beacon"]
        assert row.created_by == "alice"

        listing = await runbooks_svc.list_all(db)
        assert [r.title for r in listing] == ["Beaconing triage"]

        fetched = await runbooks_svc.get(db, row.id)
        assert fetched is not None and fetched.id == row.id
    await engine.dispose()


async def test_create_normalizes_csv_and_whitespace(settings_kratos: Settings) -> None:
    engine, maker = await _db(settings_kratos)
    async with maker() as db:
        # tags/linked_rules accept a comma/newline string and get cleaned to lists.
        row = await runbooks_svc.create(
            db,
            title="Mixed input",
            tags="  scan , recon ,\n",  # type: ignore[arg-type]
            linked_rules="ruleA,ruleB",  # type: ignore[arg-type]
        )
        assert row.tags == ["scan", "recon"]
        assert row.linked_rules == ["ruleA", "ruleB"]
    await engine.dispose()


async def test_update_patches_only_given_fields(settings_kratos: Settings) -> None:
    engine, maker = await _db(settings_kratos)
    async with maker() as db:
        row = await runbooks_svc.create(
            db, title="Original", content="body", tags=["a"], linked_rules=["r1"]
        )
        updated = await runbooks_svc.update(db, row.id, title="Renamed")
        assert updated is not None
        assert updated.title == "Renamed"
        # untouched fields survive
        assert updated.content == "body"
        assert updated.tags == ["a"]
        assert updated.linked_rules == ["r1"]

        # patch tags + content only
        updated2 = await runbooks_svc.update(db, row.id, content="new body", tags=["b", "c"])
        assert updated2 is not None
        assert updated2.content == "new body"
        assert updated2.tags == ["b", "c"]
        assert updated2.title == "Renamed"

        # missing id -> None
        assert await runbooks_svc.update(db, 9999, title="nope") is None
    await engine.dispose()


async def test_delete(settings_kratos: Settings) -> None:
    engine, maker = await _db(settings_kratos)
    async with maker() as db:
        row = await runbooks_svc.create(db, title="Delete me")
        assert await runbooks_svc.delete(db, row.id) is True
        assert await runbooks_svc.get(db, row.id) is None
        # deleting again is False
        assert await runbooks_svc.delete(db, row.id) is False
        assert await runbooks_svc.delete(db, 9999) is False
    await engine.dispose()


# ---------------------------------------------------------------------------
# Search ranking: rule-link > tag > keyword overlap
# ---------------------------------------------------------------------------


async def test_search_rule_link_beats_tag_beats_keyword(settings_kratos: Settings) -> None:
    engine, maker = await _db(settings_kratos)
    async with maker() as db:
        # A: only a keyword hit in the content.
        kw = await runbooks_svc.create(
            db, title="Generic notes", content="something about beacon traffic"
        )
        # B: a tag hit.
        tagged = await runbooks_svc.create(
            db, title="Tag match", content="unrelated", tags=["beacon"]
        )
        # C: a rule-link hit (strongest).
        linked = await runbooks_svc.create(
            db,
            title="Rule match",
            content="unrelated",
            linked_rules=["ET MALWARE Beacon"],
        )

        results = await runbooks_svc.search(db, "beacon", k=5, rule_name="ET MALWARE Beacon")
        ids_in_order = [r["id"] for r in results]
        # rule-link first, then tag, then keyword
        assert ids_in_order[0] == linked.id
        assert ids_in_order[1] == tagged.id
        assert ids_in_order[2] == kw.id
        # score is strictly decreasing across the tiers
        scores = [r["score"] for r in results]
        assert scores[0] > scores[1] > scores[2]
        # tool-shape contract
        assert set(results[0].keys()) == {"id", "title", "content", "score", "source"}
        assert results[0]["source"] == "operator_runbook"
    await engine.dispose()


async def test_search_respects_k(settings_kratos: Settings) -> None:
    engine, maker = await _db(settings_kratos)
    async with maker() as db:
        for i in range(5):
            await runbooks_svc.create(db, title=f"Scan runbook {i}", tags=["scan"])
        results = await runbooks_svc.search(db, "scan", k=2)
        assert len(results) == 2
    await engine.dispose()


async def test_search_empty_query_and_k_guards(settings_kratos: Settings) -> None:
    engine, maker = await _db(settings_kratos)
    async with maker() as db:
        await runbooks_svc.create(db, title="Something", tags=["scan"])
        # empty query + no rule_name -> nothing to match on
        assert await runbooks_svc.search(db, "", k=5) == []
        # k <= 0 -> empty
        assert await runbooks_svc.search(db, "scan", k=0) == []
        # a non-matching query -> empty (no score > 0)
        assert await runbooks_svc.search(db, "wholly-unrelated-token", k=5) == []
    await engine.dispose()


async def test_search_rule_name_only_matches_linked(settings_kratos: Settings) -> None:
    engine, maker = await _db(settings_kratos)
    async with maker() as db:
        linked = await runbooks_svc.create(db, title="Linked", linked_rules=["ET SCAN Nmap"])
        await runbooks_svc.create(db, title="Unlinked", tags=["misc"])
        # empty query but a rule_name still returns the rule-linked runbook
        results = await runbooks_svc.search(db, "", k=5, rule_name="ET SCAN Nmap")
        assert [r["id"] for r in results] == [linked.id]
    await engine.dispose()


# ---------------------------------------------------------------------------
# lookup_runbook tool: returns operator runbooks via the injected sessionmaker
# ---------------------------------------------------------------------------


async def test_lookup_runbook_returns_operator_runbooks(settings_kratos: Settings) -> None:
    engine, maker = await _db(settings_kratos)
    async with maker() as db:
        await runbooks_svc.create(
            db,
            title="Triage a beaconing alert",
            content="Confirm periodicity and destination reputation.",
            tags=["beacon"],
        )
    result = await lookup_runbook("how do I triage a beaconing alert", k=5, db_sessionmaker=maker)
    assert len(result) == 1
    assert result[0]["title"] == "Triage a beaconing alert"
    assert result[0]["source"] == "operator_runbook"
    await engine.dispose()


async def test_lookup_runbook_no_sessionmaker_returns_empty() -> None:
    # CLI / eval / no-DB path is unchanged: returns [].
    assert await lookup_runbook("anything", k=5) == []


async def test_lookup_runbook_invalid_k_rejected() -> None:
    with pytest.raises(ValueError, match="k must be positive"):
        await lookup_runbook("anything", k=0)


# ---------------------------------------------------------------------------
# Endpoints: GET/POST/PUT/DELETE /runbooks + admin gate
# ---------------------------------------------------------------------------


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
    yield from _client(settings_kratos)


def test_runbooks_crud_roundtrip(client: TestClient) -> None:
    # empty to start
    assert client.get("/api/v1/runbooks").json() == []

    # create
    resp = client.post(
        "/api/v1/runbooks",
        json={
            "title": "Scan triage",
            "content": "Check the source is an authorized scanner.",
            "tags": ["scan", "recon"],
            "linked_rules": ["ET SCAN Nmap"],
        },
    )
    assert resp.status_code == 200
    created = resp.json()
    assert created["title"] == "Scan triage"
    assert created["tags"] == ["scan", "recon"]
    assert created["linked_rules"] == ["ET SCAN Nmap"]
    assert created["created_by"] == "anonymous"  # identify_caller w/o a session
    rb_id = created["id"]

    # list shows it
    listing = client.get("/api/v1/runbooks").json()
    assert [r["title"] for r in listing] == ["Scan triage"]

    # update
    upd = client.put(
        f"/api/v1/runbooks/{rb_id}",
        json={"title": "Scan triage (v2)", "tags": ["scan"]},
    )
    assert upd.status_code == 200
    assert upd.json()["title"] == "Scan triage (v2)"
    assert upd.json()["tags"] == ["scan"]
    assert upd.json()["content"] == "Check the source is an authorized scanner."

    # delete
    rm = client.delete(f"/api/v1/runbooks/{rb_id}")
    assert rm.status_code == 200
    assert rm.json() == {"deleted": True}
    assert client.get("/api/v1/runbooks").json() == []


def test_update_missing_runbook_404(client: TestClient) -> None:
    resp = client.put("/api/v1/runbooks/9999", json={"title": "nope"})
    assert resp.status_code == 404


def test_delete_missing_runbook_404(client: TestClient) -> None:
    resp = client.delete("/api/v1/runbooks/9999")
    assert resp.status_code == 404


def test_create_runbook_requires_title(client: TestClient) -> None:
    resp = client.post("/api/v1/runbooks", json={"content": "no title"})
    assert resp.status_code == 422
