from __future__ import annotations

from datetime import timedelta

from soc_ai.config import Settings
from soc_ai.store import chat as chat_svc
from soc_ai.store import investigations as inv_svc
from soc_ai.store.auth import utcnow
from soc_ai.store.db import make_engine, make_sessionmaker, run_migrations
from soc_ai.store.models import ChatMessage


async def test_get_message(settings_kratos: Settings) -> None:
    engine = make_engine(settings_kratos)
    await run_migrations(engine)
    maker = make_sessionmaker(engine)
    async with maker() as db:
        inv = await inv_svc.create(db, alert_es_id="ev-m1", started_by="t")
        msg = await chat_svc.create_pending_assistant(db, inv.id)
        await chat_svc.finish_assistant(db, msg.id, content="hi", status="done", meta={"k": 1})
    async with maker() as db:
        got = await chat_svc.get_message(db, msg.id)
        assert got is not None and got.content == "hi" and got.meta == {"k": 1}
    await engine.dispose()


async def test_reap_stale_pending_marks_pending_error_leaves_others(
    settings_kratos: Settings,
) -> None:
    """reap_stale_pending(older_than=None) marks every pending assistant row
    error (with a user-facing note) and leaves done/error rows untouched."""
    engine = make_engine(settings_kratos)
    await run_migrations(engine)
    maker = make_sessionmaker(engine)
    async with maker() as db:
        inv = await inv_svc.create(db, alert_es_id="ev-reap", started_by="t")
        pend = await chat_svc.create_pending_assistant(db, inv.id)
        done = await chat_svc.create_pending_assistant(db, inv.id)
        await chat_svc.finish_assistant(db, done.id, content="answer", status="done")
        err = await chat_svc.create_pending_assistant(db, inv.id)
        await chat_svc.finish_assistant(db, err.id, content="boom", status="error")
        # A user row is never assistant-pending; it must be ignored.
        user = await chat_svc.add_user_message(db, inv.id, "a question")

        n = await chat_svc.reap_stale_pending(db, older_than=None)
        assert n == 1

        reaped = await db.get(ChatMessage, pend.id)
        assert reaped is not None
        assert reaped.status == "error"
        assert "interrupted" in reaped.content
        assert "ask again" in reaped.content
        # done / error / user rows untouched
        assert (await db.get(ChatMessage, done.id)).status == "done"
        assert (await db.get(ChatMessage, done.id)).content == "answer"
        assert (await db.get(ChatMessage, err.id)).status == "error"
        assert (await db.get(ChatMessage, err.id)).content == "boom"
        assert (await db.get(ChatMessage, user.id)).status == "done"
    await engine.dispose()


async def test_reap_stale_pending_only_reaps_old_when_age_set(
    settings_kratos: Settings,
) -> None:
    """A positive older_than reaps only rows older than it; a fresh turn is spared."""
    engine = make_engine(settings_kratos)
    await run_migrations(engine)
    maker = make_sessionmaker(engine)
    async with maker() as db:
        inv = await inv_svc.create(db, alert_es_id="ev-age", started_by="t")
        fresh = await chat_svc.create_pending_assistant(db, inv.id)
        stale = await chat_svc.create_pending_assistant(db, inv.id)
        # backdate the stale row's created_at past the cutoff
        stale_row = await db.get(ChatMessage, stale.id)
        assert stale_row is not None
        stale_row.created_at = utcnow() - timedelta(minutes=60)
        await db.commit()

        n = await chat_svc.reap_stale_pending(db, older_than=timedelta(minutes=30))
        assert n == 1
        assert (await db.get(ChatMessage, stale.id)).status == "error"
        assert (await db.get(ChatMessage, fresh.id)).status == "pending"
    await engine.dispose()


async def test_reap_stale_pending_returns_zero_when_nothing_pending(
    settings_kratos: Settings,
) -> None:
    engine = make_engine(settings_kratos)
    await run_migrations(engine)
    maker = make_sessionmaker(engine)
    async with maker() as db:
        inv = await inv_svc.create(db, alert_es_id="ev-none", started_by="t")
        done = await chat_svc.create_pending_assistant(db, inv.id)
        await chat_svc.finish_assistant(db, done.id, content="ok", status="done")
        assert await chat_svc.reap_stale_pending(db, older_than=None) == 0
        assert await chat_svc.reap_stale_pending(db, older_than=timedelta(minutes=30)) == 0
    await engine.dispose()
