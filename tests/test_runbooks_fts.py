"""Tests for the FTS5-first runbook retrieval (E4.1, migration 0017).

Covers: the migration creates the ``runbook_fts`` external-content index + its
sync triggers; BM25 ranking respects the tag ≫ title > content column weights;
the index tracks INSERT/UPDATE/DELETE through the ORM write paths; the MATCH
expression is injection-proof (quotes/parens/operators in the query never reach
FTS syntax); the rule-link boost still outranks every BM25 hit; and dropping
the FTS objects (≈ an FTS5-less SQLite / pre-0017 DB) falls back to the legacy
in-process scorer with the identical tool contract.

The legacy ranking semantics themselves stay covered by tests/test_runbooks.py
(those tests now exercise the FTS path, since a head-migrated DB has the index;
the fallback test here re-runs the ranking assertions on the legacy path).
"""

from __future__ import annotations

from soc_ai.config import Settings
from soc_ai.store import runbooks as runbooks_svc
from soc_ai.store.db import make_engine, make_sessionmaker, run_migrations
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker


async def _db(settings: Settings) -> tuple[AsyncEngine, async_sessionmaker[AsyncSession]]:
    engine = make_engine(settings)
    await run_migrations(engine)
    return engine, make_sessionmaker(engine)


async def _drop_fts(engine: AsyncEngine) -> None:
    """Simulate an FTS5-less install / pre-0017 DB: remove the index + triggers.

    Triggers must go first — with the virtual table gone but a trigger left
    behind, every runbook INSERT would error inside the trigger body.
    """
    async with engine.begin() as conn:
        for name in ("runbook_fts_au", "runbook_fts_ad", "runbook_fts_ai"):
            await conn.execute(text(f"DROP TRIGGER IF EXISTS {name}"))
        await conn.execute(text("DROP TABLE IF EXISTS runbook_fts"))


# ---------------------------------------------------------------------------
# Migration 0017: FTS index + triggers + the embedding side table exist
# ---------------------------------------------------------------------------


async def test_migration_creates_fts_index_triggers_and_embedding_table(
    settings_kratos: Settings,
) -> None:
    engine, _maker = await _db(settings_kratos)
    async with engine.connect() as conn:
        rows = await conn.execute(text("SELECT type, name FROM sqlite_master"))
        objects = {(t, n) for t, n in rows.all()}
    names = {n for _t, n in objects}
    assert "runbook_fts" in names
    assert {"runbook_fts_ai", "runbook_fts_ad", "runbook_fts_au"} <= {
        n for t, n in objects if t == "trigger"
    }
    assert "runbook_embedding" in names
    await engine.dispose()


async def test_migration_backfills_preexisting_rows(settings_kratos: Settings) -> None:
    """A runbook that EXISTS when 0017 runs (an upgraded install) is indexed by
    the migration's backfill — searchable without ever being re-written."""
    from alembic import command
    from soc_ai.store.db import _migration_config
    from sqlalchemy import Connection

    def _upgrade_to(connection: Connection, rev: str) -> None:
        cfg = _migration_config()
        cfg.attributes["connection"] = connection
        command.upgrade(cfg, rev)

    engine = make_engine(settings_kratos)
    # Migrate only to 0016 (pre-FTS), author a runbook, THEN land 0017.
    async with engine.begin() as conn:
        await conn.run_sync(_upgrade_to, "0016")
    async with engine.begin() as conn:
        await conn.execute(
            text(
                "INSERT INTO runbook (title, content, tags, linked_rules) "
                "VALUES ('Beacon triage', 'periodicity checks', '[]', '[]')"
            )
        )
    async with engine.begin() as conn:
        await conn.run_sync(_upgrade_to, "head")

    maker = make_sessionmaker(engine)
    async with maker() as db:
        results = await runbooks_svc.search(db, "beacon", k=5)
    assert [r["title"] for r in results] == ["Beacon triage"]
    await engine.dispose()


# ---------------------------------------------------------------------------
# BM25 ranking + rule-link boost on the FTS path
# ---------------------------------------------------------------------------


async def test_fts_ranks_tag_over_title_over_content(settings_kratos: Settings) -> None:
    """The bm25() per-column weights mirror the legacy scheme: a tag hit beats a
    title hit beats a content hit for the same term."""
    engine, maker = await _db(settings_kratos)
    async with maker() as db:
        content_hit = await runbooks_svc.create(
            db, title="Generic notes", content="something about beacon traffic"
        )
        title_hit = await runbooks_svc.create(db, title="Beacon triage", content="unrelated")
        tag_hit = await runbooks_svc.create(
            db, title="Tagged", content="unrelated", tags=["beacon"]
        )

        results = await runbooks_svc.search(db, "beacon", k=5)
        assert [r["id"] for r in results] == [tag_hit.id, title_hit.id, content_hit.id]
        scores = [r["score"] for r in results]
        assert scores[0] > scores[1] > scores[2]
    await engine.dispose()


async def test_fts_rule_link_outranks_bm25_even_with_zero_text_overlap(
    settings_kratos: Settings,
) -> None:
    """A rule-linked runbook whose text shares NOTHING with the query still ranks
    first — the boost is merged in independently of the MATCH."""
    engine, maker = await _db(settings_kratos)
    async with maker() as db:
        keyword = await runbooks_svc.create(db, title="Beacon triage", content="beacon beacon")
        linked = await runbooks_svc.create(
            db, title="Rule guidance", content="unrelated", linked_rules=["ET MALWARE Beacon"]
        )
        results = await runbooks_svc.search(db, "beacon", k=5, rule_name="ET MALWARE Beacon")
        assert [r["id"] for r in results] == [linked.id, keyword.id]
        assert results[0]["score"] > results[1]["score"]
        # tool-shape contract holds on the FTS path
        assert set(results[0].keys()) == {"id", "title", "content", "score", "source"}
        assert results[0]["source"] == "operator_runbook"
    await engine.dispose()


async def test_fts_prefix_matches_partial_last_token(settings_kratos: Settings) -> None:
    """The LAST query token gets the prefix form, so a partially-typed trailing
    word ("beaco") still finds "beacon"."""
    engine, maker = await _db(settings_kratos)
    async with maker() as db:
        rb = await runbooks_svc.create(db, title="Beacon triage", content="periodicity")
        results = await runbooks_svc.search(db, "triage beaco", k=5)
        assert [r["id"] for r in results] == [rb.id]
    await engine.dispose()


# ---------------------------------------------------------------------------
# Trigger sync: the index tracks ORM INSERT / UPDATE / DELETE
# ---------------------------------------------------------------------------


async def test_fts_index_tracks_insert_update_delete(settings_kratos: Settings) -> None:
    engine, maker = await _db(settings_kratos)
    async with maker() as db:
        rb = await runbooks_svc.create(db, title="Kerberoasting triage", content="spn checks")
        assert [r["id"] for r in await runbooks_svc.search(db, "kerberoasting", k=5)] == [rb.id]

        # UPDATE: the old term stops matching, the new one starts.
        await runbooks_svc.update(db, rb.id, title="Golden ticket triage")
        assert await runbooks_svc.search(db, "kerberoasting", k=5) == []
        assert [r["id"] for r in await runbooks_svc.search(db, "golden ticket", k=5)] == [rb.id]

        # DELETE: gone from the index entirely.
        await runbooks_svc.delete(db, rb.id)
        assert await runbooks_svc.search(db, "golden ticket", k=5) == []
    await engine.dispose()


# ---------------------------------------------------------------------------
# MATCH-injection safety: raw user text never reaches FTS syntax
# ---------------------------------------------------------------------------


async def test_fts_match_injection_is_safe(settings_kratos: Settings) -> None:
    """Queries stuffed with FTS5 syntax (quotes, parens, operators, NEAR, column
    filters) neither raise nor 500 — they degrade to their alphanumeric tokens."""
    engine, maker = await _db(settings_kratos)
    async with maker() as db:
        rb = await runbooks_svc.create(db, title="Beacon triage", content="periodicity checks")
        hostile = [
            'beacon" OR "x',
            "beacon AND (title:*)",
            'NEAR(beacon "x", 2)',
            "((((",
            '"unbalanced',
            "beacon*)-",
            "-beacon NOT title:x",
        ]
        for query in hostile:
            results = await runbooks_svc.search(db, query, k=5)
            assert isinstance(results, list)  # never raises
            # every hostile variant still carries the token "beacon" → still a hit
            if "beacon" in query:
                assert rb.id in [r["id"] for r in results]
        # pure-symbol query → no usable tokens → empty, not an error
        assert await runbooks_svc.search(db, '#!"()*', k=5) == []
    await engine.dispose()


# ---------------------------------------------------------------------------
# Fallback: no FTS objects → the legacy in-process scorer, identical contract
# ---------------------------------------------------------------------------


async def test_fallback_to_legacy_scorer_when_fts_missing(settings_kratos: Settings) -> None:
    """With the FTS index gone (FTS5-less SQLite / pre-0017 DB), search() falls
    back to the legacy scorer: same ranking scheme, same return shape."""
    engine, maker = await _db(settings_kratos)
    await _drop_fts(engine)
    async with maker() as db:
        kw = await runbooks_svc.create(
            db, title="Generic notes", content="something about beacon traffic"
        )
        tagged = await runbooks_svc.create(db, title="Tag match", content="x", tags=["beacon"])
        linked = await runbooks_svc.create(
            db, title="Rule match", content="x", linked_rules=["ET MALWARE Beacon"]
        )

        results = await runbooks_svc.search(db, "beacon", k=5, rule_name="ET MALWARE Beacon")
        assert [r["id"] for r in results] == [linked.id, tagged.id, kw.id]
        scores = [r["score"] for r in results]
        assert scores[0] > scores[1] > scores[2]
        assert set(results[0].keys()) == {"id", "title", "content", "score", "source"}
        assert results[0]["source"] == "operator_runbook"

        # the guards behave identically on the fallback path
        assert await runbooks_svc.search(db, "", k=5) == []
        assert await runbooks_svc.search(db, "beacon", k=0) == []
        assert await runbooks_svc.search(db, "wholly-unrelated-token", k=5) == []

        # the session stays usable after the OperationalError → rollback dance
        assert await runbooks_svc.get(db, linked.id) is not None
    await engine.dispose()
