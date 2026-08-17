"""Tests for the dashboard general-chat store + the 0025 migration.

Mirrors tests/test_chat_store.py, because the general chat store deliberately
mirrors ``soc_ai.store.chat`` function-for-function (a future merge of the two
should be a rename, not a redesign). The extra ground this file covers is what
makes the general chat *different*: a per-user rolling ``thread_key`` instead of
an investigation FK, a trim that keeps the single persistent thread bounded, and
the two isolation guarantees — its reaper must not touch investigation chat, and
its turns must never land in the ``chat_memory`` projection.
"""

from __future__ import annotations

from datetime import timedelta

from alembic import command
from soc_ai.config import Settings
from soc_ai.store import chat as chat_svc
from soc_ai.store import general_chat as gc_svc
from soc_ai.store import investigations as inv_svc
from soc_ai.store.auth import utcnow
from soc_ai.store.db import _migration_config, make_engine, make_sessionmaker, run_migrations
from soc_ai.store.models import ChatMemory, ChatMessage, GeneralChatMessage
from sqlalchemy import Connection, func, inspect, select, text

THREAD = "alice"
OTHER = "token:ci"


async def _db(settings: Settings):  # type: ignore[no-untyped-def]
    engine = make_engine(settings)
    await run_migrations(engine)
    return engine, make_sessionmaker(engine)


def _downgrade_to_0024(connection: Connection) -> None:
    cfg = _migration_config()
    cfg.attributes["connection"] = connection
    command.downgrade(cfg, "0024")


def _upgrade_to(connection: Connection, revision: str) -> None:
    """Migrate to a NAMED revision instead of ``head``.

    Lets this file pin the revision it is about (0025) without pinning the
    global head, which moves for reasons that have nothing to do with general
    chat.
    """
    cfg = _migration_config()
    cfg.attributes["connection"] = connection
    command.upgrade(cfg, revision)


# ---------------------------------------------------------------------------
# Migration
# ---------------------------------------------------------------------------


async def test_migration_creates_general_chat_table(settings_kratos: Settings) -> None:
    """0025 — and only 0025 — brings the table and its index into being.

    Stepping 0024 → 0025 by name, rather than asserting the stamped head equals
    "0025", is deliberate. The repo keeps exactly ONE head canary
    (tests/test_hunts_store.py::test_migration_at_head_is_current, bumped with a
    chain comment on every migration). A second head assertion inside a feature
    test goes red for migrations that have nothing to do with general chat, and
    teaches whoever hits it to edit a number without reading why.
    """
    engine = make_engine(settings_kratos)
    async with engine.begin() as conn:
        await conn.run_sync(_upgrade_to, "0024")
    async with engine.connect() as conn:
        tables = await conn.run_sync(lambda sc: inspect(sc).get_table_names())
        assert "general_chat_messages" not in tables

    async with engine.begin() as conn:
        await conn.run_sync(_upgrade_to, "0025")
    async with engine.connect() as conn:
        tables = await conn.run_sync(lambda sc: inspect(sc).get_table_names())
        assert "general_chat_messages" in tables
        indexes = await conn.run_sync(lambda sc: inspect(sc).get_indexes("general_chat_messages"))
        assert "ix_general_chat_messages_thread_key" in {ix["name"] for ix in indexes}
    await engine.dispose()


async def test_migration_leaves_chat_messages_alone(settings_kratos: Settings) -> None:
    """The whole point of a separate table: ``chat_messages.investigation_id``
    keeps its NOT NULL + FK, so no live analyst history is rebuilt."""
    engine, _maker = await _db(settings_kratos)
    async with engine.connect() as conn:
        cols = await conn.run_sync(lambda sc: inspect(sc).get_columns("chat_messages"))
        inv_col = next(c for c in cols if c["name"] == "investigation_id")
        assert inv_col["nullable"] is False
        gc_cols = await conn.run_sync(
            lambda sc: inspect(sc).get_columns("general_chat_messages"),
        )
        names = {c["name"] for c in gc_cols}
        assert names == {"id", "thread_key", "role", "content", "status", "meta", "created_at"}
        # No FK on the new table — a thread key is an actor string, not a row.
        fks = await conn.run_sync(lambda sc: inspect(sc).get_foreign_keys("general_chat_messages"))
        assert fks == []
    await engine.dispose()


async def test_orm_model_matches_the_migrated_schema(settings_kratos: Settings) -> None:
    """The ORM metadata and the migration must agree, column for column —
    where they drift, ``alembic revision --autogenerate`` proposes dropping
    whatever it cannot see in the models."""
    engine, _maker = await _db(settings_kratos)
    async with engine.connect() as conn:
        cols = await conn.run_sync(
            lambda sc: inspect(sc).get_columns("general_chat_messages"),
        )
    assert {c.name for c in GeneralChatMessage.__table__.columns} == {c["name"] for c in cols}
    await engine.dispose()


async def test_downgrade_drops_the_table_and_replays(settings_kratos: Settings) -> None:
    # A downgrade that leaves the index behind fails on the way back up.
    engine, _maker = await _db(settings_kratos)
    async with engine.begin() as conn:
        await conn.run_sync(_downgrade_to_0024)
    async with engine.connect() as conn:
        tables = await conn.run_sync(lambda sc: inspect(sc).get_table_names())
        assert "general_chat_messages" not in tables
        assert "chat_messages" in tables  # investigation chat is untouched either way
        head = await conn.execute(text("SELECT version_num FROM alembic_version"))
        assert head.scalar_one() == "0024"

    await run_migrations(engine)
    async with engine.connect() as conn:
        tables = await conn.run_sync(lambda sc: inspect(sc).get_table_names())
        assert "general_chat_messages" in tables
    await engine.dispose()


# ---------------------------------------------------------------------------
# Turn lifecycle (mirrors chat.py)
# ---------------------------------------------------------------------------


async def test_user_turn_then_answer_roundtrip(settings_kratos: Settings) -> None:
    engine, maker = await _db(settings_kratos)
    async with maker() as db:
        user = await gc_svc.add_user_message(db, THREAD, "what datasets do I have?")
        assert user.role == "user" and user.status == "done"
        assert user.thread_key == THREAD
        pend = await gc_svc.create_pending_assistant(db, THREAD)
        assert pend.role == "assistant" and pend.status == "pending" and pend.content == ""
        await gc_svc.finish_assistant(db, pend.id, content="six", status="done", meta={"k": 1})
    async with maker() as db:
        got = await gc_svc.get_message(db, pend.id)
        assert got is not None and got.content == "six" and got.meta == {"k": 1}
        assert got.status == "done"
    await engine.dispose()


async def test_finish_assistant_missing_row_is_a_noop(settings_kratos: Settings) -> None:
    engine, maker = await _db(settings_kratos)
    async with maker() as db:
        await gc_svc.finish_assistant(db, 4242, content="x")  # trimmed away mid-turn
        assert await gc_svc.get_message(db, 4242) is None
    await engine.dispose()


async def test_list_messages_is_thread_scoped_and_ordered(settings_kratos: Settings) -> None:
    """Two analysts share one table; neither sees the other's thread."""
    engine, maker = await _db(settings_kratos)
    async with maker() as db:
        await gc_svc.add_user_message(db, THREAD, "first")
        await gc_svc.add_user_message(db, OTHER, "not mine")
        await gc_svc.add_user_message(db, THREAD, "second")

        mine = await gc_svc.list_messages(db, THREAD)
        assert [m.content for m in mine] == ["first", "second"]
        theirs = await gc_svc.list_messages(db, OTHER)
        assert [m.content for m in theirs] == ["not mine"]
        assert await gc_svc.list_messages(db, "nobody") == []
    await engine.dispose()


async def test_list_messages_honours_limit_to_newest(settings_kratos: Settings) -> None:
    """A bounded read still returns oldest-first, so the UI never renders backwards."""
    engine, maker = await _db(settings_kratos)
    async with maker() as db:
        for i in range(6):
            await gc_svc.add_user_message(db, THREAD, f"m{i}")
        newest = await gc_svc.list_messages(db, THREAD, limit=2)
        assert [m.content for m in newest] == ["m4", "m5"]
    await engine.dispose()


async def test_history_for_agent_excludes_pending_error_and_empty(
    settings_kratos: Settings,
) -> None:
    engine, maker = await _db(settings_kratos)
    async with maker() as db:
        await gc_svc.add_user_message(db, THREAD, "q1")
        done = await gc_svc.create_pending_assistant(db, THREAD)
        await gc_svc.finish_assistant(db, done.id, content="a1", status="done")
        err = await gc_svc.create_pending_assistant(db, THREAD)
        await gc_svc.finish_assistant(db, err.id, content="boom", status="error")
        await gc_svc.add_user_message(db, THREAD, "q2")
        await gc_svc.create_pending_assistant(db, THREAD)  # the in-flight turn
        await gc_svc.add_user_message(db, OTHER, "someone else's question")

        assert await gc_svc.history_for_agent(db, THREAD) == [
            ("user", "q1"),
            ("assistant", "a1"),
            ("user", "q2"),
        ]
    await engine.dispose()


async def test_history_for_agent_is_bounded(settings_kratos: Settings) -> None:
    """A persistent thread must not grow the prompt without limit — the newest
    turns are the ones worth spending context on."""
    engine, maker = await _db(settings_kratos)
    async with maker() as db:
        for i in range(10):
            await gc_svc.add_user_message(db, THREAD, f"q{i}")
        assert await gc_svc.history_for_agent(db, THREAD, limit=3) == [
            ("user", "q7"),
            ("user", "q8"),
            ("user", "q9"),
        ]
    await engine.dispose()


# ---------------------------------------------------------------------------
# Live progress
# ---------------------------------------------------------------------------


async def test_set_progress_records_tools_and_keeps_other_meta(
    settings_kratos: Settings,
) -> None:
    engine, maker = await _db(settings_kratos)
    async with maker() as db:
        pend = await gc_svc.create_pending_assistant(db, THREAD)
        pend.meta = {"kind": "propose_hunt"}
        await db.commit()
        await gc_svc.set_progress(db, pend.id, ["dataset_inventory", "search_events"])
        row = await gc_svc.get_message(db, pend.id)
        assert row is not None and row.meta is not None
        assert row.meta["progress_tools"] == ["dataset_inventory", "search_events"]
        assert row.meta["kind"] == "propose_hunt"
    await engine.dispose()


async def test_set_progress_caps_at_last_twelve(settings_kratos: Settings) -> None:
    engine, maker = await _db(settings_kratos)
    async with maker() as db:
        pend = await gc_svc.create_pending_assistant(db, THREAD)
        await gc_svc.set_progress(db, pend.id, [f"t{i}" for i in range(20)])
        row = await gc_svc.get_message(db, pend.id)
        assert row is not None and row.meta is not None
        assert row.meta["progress_tools"] == [f"t{i}" for i in range(8, 20)]
    await engine.dispose()


async def test_set_progress_ignores_finished_or_missing_rows(
    settings_kratos: Settings,
) -> None:
    """A progress write racing the turn's completion must not resurrect it."""
    engine, maker = await _db(settings_kratos)
    async with maker() as db:
        done = await gc_svc.create_pending_assistant(db, THREAD)
        await gc_svc.finish_assistant(db, done.id, content="answer", status="done")
        await gc_svc.set_progress(db, done.id, ["late_tool"])
        row = await gc_svc.get_message(db, done.id)
        assert row is not None
        assert row.content == "answer" and row.status == "done"
        assert not (row.meta or {}).get("progress_tools")
        await gc_svc.set_progress(db, 4242, ["ghost"])  # vanished row: no raise
    await engine.dispose()


# ---------------------------------------------------------------------------
# Reaper
# ---------------------------------------------------------------------------


async def test_reap_stale_pending_marks_pending_error_leaves_others(
    settings_kratos: Settings,
) -> None:
    engine, maker = await _db(settings_kratos)
    async with maker() as db:
        pend = await gc_svc.create_pending_assistant(db, THREAD)
        done = await gc_svc.create_pending_assistant(db, THREAD)
        await gc_svc.finish_assistant(db, done.id, content="answer", status="done")
        err = await gc_svc.create_pending_assistant(db, THREAD)
        await gc_svc.finish_assistant(db, err.id, content="boom", status="error")
        user = await gc_svc.add_user_message(db, THREAD, "a question")

        assert await gc_svc.reap_stale_pending(db, older_than=None) == 1

        reaped = await db.get(GeneralChatMessage, pend.id)
        assert reaped is not None
        assert reaped.status == "error"
        assert "interrupted" in reaped.content
        assert "ask again" in reaped.content
        assert (await db.get(GeneralChatMessage, done.id)).status == "done"
        assert (await db.get(GeneralChatMessage, err.id)).content == "boom"
        assert (await db.get(GeneralChatMessage, user.id)).status == "done"
    await engine.dispose()


async def test_reap_stale_pending_only_reaps_old_when_age_set(
    settings_kratos: Settings,
) -> None:
    engine, maker = await _db(settings_kratos)
    async with maker() as db:
        fresh = await gc_svc.create_pending_assistant(db, THREAD)
        stale = await gc_svc.create_pending_assistant(db, THREAD)
        stale_row = await db.get(GeneralChatMessage, stale.id)
        assert stale_row is not None
        stale_row.created_at = utcnow() - timedelta(minutes=60)
        await db.commit()

        assert await gc_svc.reap_stale_pending(db, older_than=timedelta(minutes=30)) == 1
        assert (await db.get(GeneralChatMessage, stale.id)).status == "error"
        assert (await db.get(GeneralChatMessage, fresh.id)).status == "pending"
    await engine.dispose()


async def test_reap_stale_pending_returns_zero_when_nothing_pending(
    settings_kratos: Settings,
) -> None:
    engine, maker = await _db(settings_kratos)
    async with maker() as db:
        done = await gc_svc.create_pending_assistant(db, THREAD)
        await gc_svc.finish_assistant(db, done.id, content="ok", status="done")
        assert await gc_svc.reap_stale_pending(db, older_than=None) == 0
        assert await gc_svc.reap_stale_pending(db, older_than=timedelta(minutes=30)) == 0
    await engine.dispose()


async def test_reapers_do_not_reach_across_tables(settings_kratos: Settings) -> None:
    """Two tables, two reapers. Neither may resolve the other's in-flight turn."""
    engine, maker = await _db(settings_kratos)
    async with maker() as db:
        inv = await inv_svc.create(db, alert_es_id="ev-x", started_by="t")
        inv_pending = await chat_svc.create_pending_assistant(db, inv.id)
        gc_pending = await gc_svc.create_pending_assistant(db, THREAD)

        assert await gc_svc.reap_stale_pending(db, older_than=None) == 1
        assert (await db.get(ChatMessage, inv_pending.id)).status == "pending"

        assert await chat_svc.reap_stale_pending(db, older_than=None) == 1
        assert (await db.get(GeneralChatMessage, gc_pending.id)).status == "error"
    await engine.dispose()


# ---------------------------------------------------------------------------
# Trim
# ---------------------------------------------------------------------------


async def test_trim_thread_keeps_newest_and_spares_other_threads(
    settings_kratos: Settings,
) -> None:
    engine, maker = await _db(settings_kratos)
    async with maker() as db:
        for i in range(10):
            await gc_svc.add_user_message(db, THREAD, f"m{i}")
        for i in range(3):
            await gc_svc.add_user_message(db, OTHER, f"o{i}")

        assert await gc_svc.trim_thread(db, THREAD, keep_last=4) == 6
        assert [m.content for m in await gc_svc.list_messages(db, THREAD)] == [
            "m6",
            "m7",
            "m8",
            "m9",
        ]
        assert len(await gc_svc.list_messages(db, OTHER)) == 3
    await engine.dispose()


async def test_trim_thread_noop_under_the_cap(settings_kratos: Settings) -> None:
    engine, maker = await _db(settings_kratos)
    async with maker() as db:
        await gc_svc.add_user_message(db, THREAD, "only one")
        assert await gc_svc.trim_thread(db, THREAD, keep_last=200) == 0
        assert await gc_svc.trim_thread(db, "nobody", keep_last=200) == 0
        assert len(await gc_svc.list_messages(db, THREAD)) == 1
    await engine.dispose()


async def test_finishing_a_turn_bounds_the_thread(settings_kratos: Settings) -> None:
    """The trim has to happen without the caller remembering to ask: the thread
    is persistent and per-user, so nothing else ever prunes it."""
    engine, maker = await _db(settings_kratos)
    async with maker() as db:
        for i in range(gc_svc.MAX_THREAD_MESSAGES + 5):
            await gc_svc.add_user_message(db, THREAD, f"m{i}")
        pend = await gc_svc.create_pending_assistant(db, THREAD)
        await gc_svc.finish_assistant(db, pend.id, content="the answer", status="done")

        rows = await gc_svc.list_messages(db, THREAD)
        assert len(rows) == gc_svc.MAX_THREAD_MESSAGES
        # The turn that triggered the trim survives it.
        assert rows[-1].id == pend.id and rows[-1].content == "the answer"
        assert rows[0].content == "m6"
    await engine.dispose()


# ---------------------------------------------------------------------------
# chat_memory isolation
# ---------------------------------------------------------------------------


async def test_general_chat_never_projects_into_chat_memory(
    settings_kratos: Settings,
) -> None:
    """Design non-goal, and a deliberate one: ``chat_memory`` is recalled into
    investigation verdict prompts. Feeding a dashboard scratchpad into that
    retrieval is the prompt-poisoning failure this project keeps fighting.
    """
    engine, maker = await _db(settings_kratos)
    async with maker() as db:
        await gc_svc.add_user_message(db, THREAD, "is 192.168.10.5 a server?")
        pend = await gc_svc.create_pending_assistant(db, THREAD)
        await gc_svc.finish_assistant(db, pend.id, content="yes, a hypervisor", status="done")
        assert await db.scalar(select(func.count(ChatMemory.id))) == 0
    await engine.dispose()
