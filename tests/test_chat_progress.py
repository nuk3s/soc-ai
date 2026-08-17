"""Live tool progress during a chat turn (dogfood 2026-08-06).

The chat was "nothing, then everything": the poll returned only `pending: true`
until the whole turn finished, so a multi-tool investigation looked identical to
a hung one and analysts lost patience. Each tool call now lands on the pending
row and rides the existing poll.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock

from soc_ai.agent.context import InvestigationContext


def _ctx(**over: Any) -> InvestigationContext:
    base: dict[str, Any] = {
        "settings": MagicMock(),
        "auth": MagicMock(),
        "elastic": MagicMock(),
    }
    base.update(over)
    return InvestigationContext(**base)


def test_context_progress_callback_defaults_off() -> None:
    """Default path keeps no extra frame in the tool stack."""
    assert _ctx().on_tool_call is None


async def test_registered_tools_report_their_name_on_start() -> None:
    """The choke point fires for tools generally — no per-tool wiring."""
    from soc_ai.agent.toolset import _progress

    seen: list[str] = []

    async def t_query_events_oql(**_: Any) -> dict[str, Any]:
        return {"ok": True}

    wrapped = _progress(_ctx(on_tool_call=seen.append), t_query_events_oql)
    assert await wrapped() == {"ok": True}
    assert seen == ["t_query_events_oql"]


async def test_progress_sink_failure_never_breaks_the_tool() -> None:
    """Progress is cosmetic; a raising sink must not fail the tool call."""
    from soc_ai.agent.toolset import _progress

    def boom(_name: str) -> None:
        raise RuntimeError("sink exploded")

    async def t_thing(**_: Any) -> str:
        return "result"

    wrapped = _progress(_ctx(on_tool_call=boom), t_thing)
    assert await wrapped() == "result"


async def test_progress_persists_only_while_pending(tmp_path) -> None:
    """A write that lands after the turn finished must be a no-op, not clobber
    the finished row's meta."""
    from soc_ai.config import Settings
    from soc_ai.store import chat as chat_svc
    from soc_ai.store import investigations as inv_svc
    from soc_ai.store.db import make_engine, make_sessionmaker, run_migrations

    from tests.conftest import _base_settings_kwargs

    settings = Settings(**{**_base_settings_kwargs(), "db_path": str(tmp_path / "p.db")})
    engine = make_engine(settings)
    await run_migrations(engine)
    maker = make_sessionmaker(engine)
    async with maker() as db:
        inv = await inv_svc.create(db, alert_es_id="a1", started_by="t")
        msg = await chat_svc.create_pending_assistant(db, inv.id)
        await chat_svc.set_progress(db, msg.id, ["t_query_events_oql", "t_enrich_ip"])
        thread = await chat_svc.list_messages(db, inv.id)
        pending = [m for m in thread if m.status == "pending"][-1]
        assert pending.meta["progress_tools"] == ["t_query_events_oql", "t_enrich_ip"]

        await chat_svc.finish_assistant(db, msg.id, content="done", status="done", meta={})
        # Late write after completion: ignored.
        await chat_svc.set_progress(db, msg.id, ["t_late"])
        rows = await chat_svc.list_messages(db, inv.id)
        done = next(m for m in rows if m.id == msg.id)
        assert "progress_tools" not in (done.meta or {})
    await engine.dispose()


def test_thread_response_exposes_progress() -> None:
    """The poll carries progress so the client needs no new endpoint."""
    from soc_ai.api.webui.routes_chat import _thread

    pending = MagicMock(
        status="pending",
        meta={"progress_tools": ["t_query_events_oql"]},
        role="assistant",
        content="",
        id=2,
    )
    out = _thread([pending])
    assert out.pending is True
    assert out.progress_tools == ["t_query_events_oql"]


def test_thread_progress_empty_when_idle() -> None:
    from soc_ai.api.webui.routes_chat import _thread

    done = MagicMock(status="done", meta={}, role="assistant", content="hi", id=1)
    out = _thread([done])
    assert out.pending is False
    assert out.progress_tools == []
