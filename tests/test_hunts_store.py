"""Tests for the hunts store service + the 0010 migration.

Mirrors tests/test_store_investigations.py: exercises create / append_events /
finalize / get_with_events / list_recent / reap_stale_running / delete against a
real SQLite file migrated to head, and asserts the 0010 migration creates the
``hunts`` + ``hunt_events`` tables (with the hunt_events index). Uses the
``settings_kratos`` fixture, which the autouse ``clean_env`` fixture isolates to
a per-test temp dir (so the sqlite file is fresh each test).
"""

from __future__ import annotations

from soc_ai.config import Settings
from soc_ai.store import hunts as hunt_svc
from soc_ai.store.db import make_engine, make_sessionmaker, run_migrations
from sqlalchemy import inspect, text

REPORT = {
    "findings": [
        {
            "title": "Beaconing to rare external IP",
            "detail": "10.0.0.5 contacted 203.0.113.9 on a fixed 60s cadence.",
            "severity": "high",
            "hosts": ["10.0.0.5"],
            "citations": ["es-abc"],
        }
    ],
    "narrative": "One host is beaconing to a rare external IP.",
    "affected_hosts": ["10.0.0.5"],
    "mitre_techniques": ["T1071.001"],
    "recommended_actions": [{"title": "Isolate 10.0.0.5", "rationale": "Active C2 suspected."}],
    "confidence": 0.7,
}


async def _db(settings: Settings):  # type: ignore[no-untyped-def]
    engine = make_engine(settings)
    await run_migrations(engine)
    return engine, make_sessionmaker(engine)


async def test_migration_creates_hunts_tables(settings_kratos: Settings) -> None:
    engine, _maker = await _db(settings_kratos)
    async with engine.connect() as conn:
        tables = await conn.run_sync(lambda sc: inspect(sc).get_table_names())
        assert "hunts" in tables
        assert "hunt_events" in tables
        indexes = await conn.run_sync(lambda sc: inspect(sc).get_indexes("hunt_events"))
        assert "ix_hunt_events_hunt_id" in {ix["name"] for ix in indexes}
    await engine.dispose()


async def test_migration_at_head_is_current(settings_kratos: Settings) -> None:
    # The store schema migrates cleanly to the current head. Bump this when a new
    # migration lands (0010 hunts → 0011 backtests → 0012 runbooks → 0013
    # hunt_objective_hash → 0014 hunt_schedules → 0015 assignment_state → 0016
    # hunt_templates → 0017 runbook_fts → 0018 chat_fts → 0019 quality_snapshots
    # → 0020 runbook_draft → …).
    engine, _maker = await _db(settings_kratos)
    async with engine.connect() as conn:
        row = await conn.execute(text("SELECT version_num FROM alembic_version"))
        assert row.scalar_one() == "0020"
    await engine.dispose()


async def test_create_and_get(settings_kratos: Settings) -> None:
    engine, maker = await _db(settings_kratos)
    async with maker() as db:
        hunt = await hunt_svc.create(db, objective="hunt for beaconing", started_by="admin")
        assert hunt.id and len(hunt.id) == 26  # ULID
        assert hunt.status == "running"
        assert hunt.kind == "chat"
        got = await hunt_svc.get_with_events(db, hunt.id)
        assert got is not None
        row, events = got
        assert row.objective == "hunt for beaconing"
        assert row.started_by == "admin"
        assert events == []
        # unknown id → None
        assert await hunt_svc.get_with_events(db, "nope") is None
    await engine.dispose()


async def test_append_events_and_ordering(settings_kratos: Settings) -> None:
    engine, maker = await _db(settings_kratos)
    async with maker() as db:
        hunt = await hunt_svc.create(db, objective="x", started_by="admin")
        # Insert out of order; get_with_events must return them sequence-ordered.
        await hunt_svc.append_events(
            db,
            hunt.id,
            [
                {"sequence": 2, "kind": "tool_call", "payload": {"tool_name": "t_prevalence"}},
                {"sequence": 1, "kind": "hunt_started", "payload": {"objective": "x"}},
            ],
        )
        got = await hunt_svc.get_with_events(db, hunt.id)
        assert got is not None
        _row, events = got
        assert [e.sequence for e in events] == [1, 2]
        assert events[0].kind == "hunt_started"
        assert events[1].payload == {"tool_name": "t_prevalence"}
    await engine.dispose()


async def test_finalize_lands_report(settings_kratos: Settings) -> None:
    engine, maker = await _db(settings_kratos)
    async with maker() as db:
        hunt = await hunt_svc.create(db, objective="x", started_by="admin")
        await hunt_svc.finalize(
            db, hunt.id, status="complete", narrative=REPORT["narrative"], report=REPORT
        )
        got = await hunt_svc.get_with_events(db, hunt.id)
        assert got is not None
        row, _events = got
        assert row.status == "complete"
        assert row.narrative == REPORT["narrative"]
        assert row.report["confidence"] == 0.7
        assert row.finished_at is not None
    # finalize on a missing id is a no-op (does not raise)
    async with maker() as db:
        await hunt_svc.finalize(db, "missing", status="complete")
    await engine.dispose()


async def test_list_recent_and_status_filter(settings_kratos: Settings) -> None:
    engine, maker = await _db(settings_kratos)
    async with maker() as db:
        h1 = await hunt_svc.create(db, objective="one", started_by="a")
        h2 = await hunt_svc.create(db, objective="two", started_by="a")
        await hunt_svc.finalize(db, h1.id, status="complete", report=REPORT)
        recent = await hunt_svc.list_recent(db)
        assert [h.id for h in recent] == [h2.id, h1.id]  # newest-first
        complete = await hunt_svc.list_recent(db, status="complete")
        assert [h.id for h in complete] == [h1.id]
        running = await hunt_svc.list_recent(db, status="running")
        assert [h.id for h in running] == [h2.id]
    await engine.dispose()


async def test_reap_stale_running(settings_kratos: Settings) -> None:
    engine, maker = await _db(settings_kratos)
    async with maker() as db:
        running = await hunt_svc.create(db, objective="orphan", started_by="a")
        done = await hunt_svc.create(db, objective="done", started_by="a")
        await hunt_svc.finalize(db, done.id, status="complete", report=REPORT)
        # startup reap (older_than_minutes=None) marks every running row interrupted
        n = await hunt_svc.reap_stale_running(db, older_than_minutes=None, status="interrupted")
        assert n == 1
        got = await hunt_svc.get_with_events(db, running.id)
        assert got is not None
        assert got[0].status == "interrupted"
        assert got[0].narrative and "interrupted" in got[0].narrative.lower()
        # the completed hunt is untouched
        done_got = await hunt_svc.get_with_events(db, done.id)
        assert done_got is not None and done_got[0].status == "complete"
    await engine.dispose()


async def test_delete_removes_hunt_and_events(settings_kratos: Settings) -> None:
    engine, maker = await _db(settings_kratos)
    async with maker() as db:
        hunt = await hunt_svc.create(db, objective="x", started_by="a")
        await hunt_svc.append_events(
            db, hunt.id, [{"sequence": 1, "kind": "hunt_started", "payload": {}}]
        )
        assert await hunt_svc.delete(db, hunt.id) is True
        assert await hunt_svc.get_with_events(db, hunt.id) is None
        # deleting a missing id returns False
        assert await hunt_svc.delete(db, hunt.id) is False
    await engine.dispose()


async def test_hunt_chat_thread_round_trips(settings_kratos: Settings) -> None:
    """The hunt follow-up chat helpers store/read a thread as hunt_events keyed by
    hunt id: user turn, pending assistant, then finished; history excludes pending."""
    engine, maker = await _db(settings_kratos)
    async with maker() as db:
        hunt = await hunt_svc.create(db, objective="beaconing", started_by="a")
        await hunt_svc.finalize(db, hunt.id, status="complete", report=REPORT)
        # a real trace event first — chat rows must sequence AFTER it
        await hunt_svc.append_events(
            db, hunt.id, [{"sequence": 1, "kind": "hunt_started", "payload": {}}]
        )

        user = await hunt_svc.add_chat_user_message(db, hunt.id, "which host?")
        pending = await hunt_svc.create_pending_chat_assistant(db, hunt.id)
        assert pending.sequence > user.sequence > 1  # appended after the trace

        # while pending, history_for_agent has only the user turn (the pending
        # assistant row is excluded)
        hist = await hunt_svc.chat_history_for_agent(db, hunt.id)
        assert hist == [("user", "which host?")]

        msgs = await hunt_svc.list_chat_messages(db, hunt.id)
        assert [m.kind for m in msgs] == ["chat_user", "chat_assistant"]
        assert (msgs[1].payload or {}).get("status") == "pending"

        await hunt_svc.finish_chat_assistant(
            db,
            pending.id,
            content="10.0.0.5 was beaconing.",
            status="done",
            meta={"tools": ["t_query_events_oql"]},
        )
        msgs = await hunt_svc.list_chat_messages(db, hunt.id)
        assert (msgs[1].payload or {})["content"] == "10.0.0.5 was beaconing."
        assert (msgs[1].payload or {})["status"] == "done"
        assert (msgs[1].payload or {})["meta"]["tools"] == ["t_query_events_oql"]

        # now both turns are complete
        hist = await hunt_svc.chat_history_for_agent(db, hunt.id)
        assert hist == [("user", "which host?"), ("assistant", "10.0.0.5 was beaconing.")]

        # the chat rows are NOT part of the hunt's trace-only get_with_events? They
        # ARE hunt_events, so get_with_events returns them too (the timeline builder
        # is what filters them). Verify they co-exist with the trace event.
        got = await hunt_svc.get_with_events(db, hunt.id)
        assert got is not None
        kinds = [e.kind for e in got[1]]
        assert "hunt_started" in kinds
        assert "chat_user" in kinds and "chat_assistant" in kinds
    await engine.dispose()
