"""Tests for the Hunt Console API + the hunt agent/runner wiring.

- HuntReport pydantic schema (shape + defaults).
- build_hunt_agent produces a HuntReport (TestModel, no live LLM — mirrors
  test_agent.py's TestModel(custom_output_args=...) pattern).
- run_hunt streams hunt_started → hunt_report → done StepEvents.
- hunt_recorded_run + the HuntConsoleManager persist a complete hunt end to end.
- GET /api/v1/hunts (list) and GET /api/v1/hunts/{id} (detail) map the stored
  row + report into the frontend shape; a missing id 404s.
"""

from __future__ import annotations

import asyncio
from collections.abc import Iterator
from typing import Any
from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient
from pydantic_ai.models.test import TestModel
from soc_ai.agent.hunt import (
    HUNT_SYSTEM_PROMPT,
    HuntFinding,
    HuntReport,
    build_hunt_agent,
    build_hunt_prompt,
)
from soc_ai.agent.orchestrator import InvestigationContext
from soc_ai.api.hunt_runner import hunt_recorded_run, run_hunt
from soc_ai.config import Settings
from soc_ai.main import create_app
from soc_ai.store import hunts as hunt_svc

# A valid HuntReport the TestModel emits as the agent's structured output.
FAKE_REPORT = HuntReport(
    findings=[
        HuntFinding(
            title="Beaconing to rare external IP",
            detail="10.0.0.5 → 203.0.113.9 on a fixed 60s cadence.",
            severity="high",
            hosts=["10.0.0.5"],
            citations=["es-abc"],
        )
    ],
    narrative="One host is beaconing to a rare external IP.",
    affected_hosts=["10.0.0.5"],
    mitre_techniques=["T1071.001"],
    confidence=0.7,
)


# ── Schema ───────────────────────────────────────────────────────────────────


def test_hunt_report_defaults() -> None:
    r = HuntReport(narrative="nothing notable")
    assert r.findings == []
    assert r.affected_hosts == []
    assert r.mitre_techniques == []
    assert r.recommended_actions == []
    assert r.confidence == 0.5  # sensible mid default


def test_hunt_report_confidence_bounds() -> None:
    from pydantic import ValidationError

    with pytest.raises(ValidationError):
        HuntReport(narrative="x", confidence=1.5)


def test_build_hunt_prompt_followup() -> None:
    assert build_hunt_prompt("go") == "go"
    followup = build_hunt_prompt("refine", prior="prior narrative here")
    assert "Prior hunt so far" in followup
    assert "prior narrative here" in followup
    assert "refine" in followup


def test_hunt_prompt_is_inventory_first_and_teaches_correlation() -> None:
    """The hunt prompt must steer inventory-first hunting + correlation patterns."""
    p = HUNT_SYSTEM_PROMPT
    # Inventory-first: read the auto-discovered inventory before planning/querying.
    assert "READ THE INVENTORY FIRST" in p
    assert "Data available on this grid" in p
    # Absent-dataset handling: report the visibility gap instead of guessing.
    assert "A visibility gap is a real result." in p
    # The three correlation patterns (kill-chain, fan-out, decisive beacon/DNS C2).
    assert "Correlation patterns" in p
    assert "Kill-chain over time" in p
    assert "Fan-out around one indicator" in p
    assert "decisive C2" in p


# ── Agent wiring ─────────────────────────────────────────────────────────────


def _ctx(settings: Settings) -> InvestigationContext:
    return InvestigationContext(settings=settings, auth=AsyncMock(), elastic=AsyncMock())


def test_build_hunt_agent_emits_hunt_report(settings_kratos: Settings) -> None:
    agent = build_hunt_agent(
        TestModel(call_tools=[], custom_output_args=FAKE_REPORT),
        _ctx(settings_kratos),
        system_prompt=HUNT_SYSTEM_PROMPT.format(objective="hunt for beaconing"),
    )
    assert agent.output_type is HuntReport
    result = asyncio.run(agent.run("hunt for beaconing"))
    assert isinstance(result.output, HuntReport)
    assert result.output.findings[0].title == "Beaconing to rare external IP"


def test_hunt_online_tools_gated_by_master_toggle(settings_kratos: Settings) -> None:
    """U4: t_greynoise/t_shodan_*/t_cve_lookup are only registered on the hunt
    agent when allow_online_enrichment is on — an OFF toggle must not leave
    tools that answer 'skipped (online enrichment off)' for the model to
    waste budget on."""
    online = {"t_greynoise", "t_shodan_internetdb", "t_shodan_host", "t_cve_lookup"}
    prompt = HUNT_SYSTEM_PROMPT.format(objective="hunt for beaconing")

    assert settings_kratos.allow_online_enrichment is False  # fixture default
    agent_off = build_hunt_agent(
        TestModel(call_tools=[], custom_output_args=FAKE_REPORT),
        _ctx(settings_kratos),
        system_prompt=prompt,
    )
    names_off = set(agent_off._function_toolset.tools.keys())  # type: ignore[attr-defined]
    assert not (online & names_off), sorted(online & names_off)
    assert "t_query_events_oql" in names_off  # core read surface unaffected

    settings_on = settings_kratos.model_copy(update={"allow_online_enrichment": True})
    agent_on = build_hunt_agent(
        TestModel(call_tools=[], custom_output_args=FAKE_REPORT),
        _ctx(settings_on),
        system_prompt=prompt,
    )
    names_on = set(agent_on._function_toolset.tools.keys())  # type: ignore[attr-defined]
    assert online <= names_on, sorted(online - names_on)


def test_run_hunt_streams_report(settings_kratos: Settings) -> None:
    async def _go() -> list[Any]:
        events = []
        # Patch the model builder the runner uses so no live gateway is touched.
        with patch(
            "soc_ai.api.hunt_runner.build_investigator_model",
            return_value=TestModel(call_tools=[], custom_output_args=FAKE_REPORT),
        ):
            async for ev in run_hunt(_ctx(settings_kratos), objective="hunt for beaconing"):
                events.append(ev)
        return events

    events = asyncio.run(_go())
    kinds = [e.kind for e in events]
    assert kinds[0] == "hunt_started"
    assert "hunt_report" in kinds
    assert kinds[-1] == "done"
    report_ev = next(e for e in events if e.kind == "hunt_report")
    assert report_ev.payload["narrative"] == "One host is beaconing to a rare external IP."
    assert report_ev.payload["mitre_techniques"] == ["T1071.001"]
    done_ev = next(e for e in events if e.kind == "done")
    assert done_ev.payload["finding_count"] == 1


def test_run_hunt_budget_exhaustion_synthesizes_partial_report(settings_kratos: Settings) -> None:
    """When a hunt exhausts its budget mid-run, the runner synthesizes a PARTIAL
    report from what it gathered instead of erroring with nothing — the live
    25-minute-then-error failure mode."""
    from types import SimpleNamespace

    from pydantic_ai.exceptions import UsageLimitExceeded
    from pydantic_ai.messages import ModelResponse, TextPart

    class _BudgetRun:
        result = None

        def __init__(self) -> None:
            self._yielded = False

        async def __aenter__(self) -> _BudgetRun:
            return self

        async def __aexit__(self, *a: Any) -> bool:
            return False

        def __aiter__(self) -> _BudgetRun:
            return self

        async def __anext__(self) -> Any:
            if not self._yielded:
                self._yielded = True  # one live step, then the budget runs out
                return SimpleNamespace(
                    model_response=ModelResponse(parts=[TextPart(content="ran a query")]),
                    request=None,
                )
            raise UsageLimitExceeded("request_limit exceeded")

    class _BudgetAgent:
        def iter(self, *a: Any, **k: Any) -> _BudgetRun:
            return _BudgetRun()

    partial = HuntReport(narrative="partial — hunt was cut short", findings=[], confidence=0.2)

    async def _go() -> list[Any]:
        events = []
        with (
            patch("soc_ai.api.hunt_runner.build_hunt_agent", return_value=_BudgetAgent()),
            patch(
                "soc_ai.api.hunt_runner.build_investigator_model",
                return_value=TestModel(call_tools=[]),
            ),
            patch(
                "soc_ai.api.hunt_runner._synthesize_partial_hunt",
                AsyncMock(return_value=SimpleNamespace(output=partial)),
            ),
        ):
            async for ev in run_hunt(_ctx(settings_kratos), objective="hunt for beaconing"):
                events.append(ev)
        return events

    events = asyncio.run(_go())
    kinds = [e.kind for e in events]
    # A report was produced (from partial synthesis), NOT a bare error.
    assert "hunt_report" in kinds
    assert kinds[-1] == "done"
    assert "error" not in kinds
    report_ev = next(e for e in events if e.kind == "hunt_report")
    assert report_ev.payload["narrative"] == "partial — hunt was cut short"
    # the operator-visible note about the partial synthesis was emitted
    assert any("partial report" in str(e.payload) for e in events)


def test_run_hunt_wall_clock_timeout_synthesizes_partial_report(
    settings_kratos: Settings,
) -> None:
    """A HUNG exploration stream is bounded by ``hunt_run_timeout_s``: on the
    wall-clock backstop the runner falls through to the SAME partial-report path
    as budget exhaustion (a grounded PARTIAL report, not an empty error)."""
    from types import SimpleNamespace

    from pydantic_ai.messages import ModelResponse, TextPart

    class _HangingRun:
        result = None

        def __init__(self) -> None:
            self._yielded = False

        async def __aenter__(self) -> _HangingRun:
            return self

        async def __aexit__(self, *a: Any) -> bool:
            return False

        def __aiter__(self) -> _HangingRun:
            return self

        async def __anext__(self) -> Any:
            if not self._yielded:
                # One live step lands in `gathered`, then the stream wedges — the
                # exact "ran some queries, then the LLM hung" failure mode.
                self._yielded = True
                return SimpleNamespace(
                    model_response=ModelResponse(parts=[TextPart(content="ran a query")]),
                    request=None,
                )
            await asyncio.sleep(3600)  # hang until the wall-clock backstop cancels
            raise AssertionError("unreachable")  # pragma: no cover

    class _HangingAgent:
        def iter(self, *a: Any, **k: Any) -> _HangingRun:
            return _HangingRun()

    partial = HuntReport(narrative="partial — hunt timed out", findings=[], confidence=0.2)

    # A tiny wall-clock backstop so the hang is cut almost immediately (the one
    # live node streams first; the second __anext__ then wedges and trips it).
    settings_kratos.hunt_run_timeout_s = 1

    async def _go() -> list[Any]:
        events = []
        with (
            patch("soc_ai.api.hunt_runner.build_hunt_agent", return_value=_HangingAgent()),
            patch(
                "soc_ai.api.hunt_runner.build_investigator_model",
                return_value=TestModel(call_tools=[]),
            ),
            patch(
                "soc_ai.api.hunt_runner._synthesize_partial_hunt",
                AsyncMock(return_value=SimpleNamespace(output=partial)),
            ),
        ):
            async for ev in run_hunt(_ctx(settings_kratos), objective="hunt for beaconing"):
                events.append(ev)
        return events

    events = asyncio.run(_go())
    kinds = [e.kind for e in events]
    # The timeout routed to partial synthesis, NOT a bare error event.
    assert "hunt_report" in kinds
    assert kinds[-1] == "done"
    assert "error" not in kinds
    report_ev = next(e for e in events if e.kind == "hunt_report")
    assert report_ev.payload["narrative"] == "partial — hunt timed out"
    assert any("partial report" in str(e.payload) for e in events)


# ── Endpoints ────────────────────────────────────────────────────────────────


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


def _seed_complete_hunt(client: TestClient) -> str:
    """Insert a completed hunt (with events + a report) into the client's DB."""

    async def _go() -> str:
        maker = client.app.state.db_sessionmaker
        async with maker() as db:
            hunt = await hunt_svc.create(db, objective="hunt for beaconing", started_by="admin")
            await hunt_svc.append_events(
                db,
                hunt.id,
                [
                    {"sequence": 1, "kind": "hunt_started", "payload": {"objective": "x"}},
                    {
                        "sequence": 2,
                        "kind": "tool_call",
                        "payload": {
                            "tool_name": "t_query_events_oql",
                            "args": {"query": "event.dataset:zeek.conn"},
                            "tool_call_id": "c1",
                        },
                    },
                    {
                        "sequence": 3,
                        "kind": "tool_result",
                        "payload": {
                            "tool_name": "t_query_events_oql",
                            "result": {"total": 3},
                            "tool_call_id": "c1",
                        },
                    },
                    {
                        "sequence": 4,
                        "kind": "hunt_report",
                        "payload": FAKE_REPORT.model_dump(mode="json"),
                    },
                ],
            )
            await hunt_svc.finalize(
                db,
                hunt.id,
                status="complete",
                narrative=FAKE_REPORT.narrative,
                report=FAKE_REPORT.model_dump(mode="json"),
            )
            return hunt.id

    return asyncio.run(_go())


def test_list_hunts_empty(client: TestClient) -> None:
    resp = client.get("/api/v1/hunts")
    assert resp.status_code == 200
    assert resp.json() == []


def test_list_and_get_hunt(client: TestClient) -> None:
    hunt_id = _seed_complete_hunt(client)

    resp = client.get("/api/v1/hunts")
    assert resp.status_code == 200
    rows = resp.json()
    assert len(rows) == 1
    row = rows[0]
    assert row["id"] == hunt_id
    assert row["objective"] == "hunt for beaconing"
    assert row["status"] == "complete"
    assert row["findingCount"] == 1
    assert row["affectedHosts"] == 1

    detail = client.get(f"/api/v1/hunts/{hunt_id}")
    assert detail.status_code == 200
    body = detail.json()
    assert body["objective"] == "hunt for beaconing"
    assert body["narrative"] == FAKE_REPORT.narrative
    assert body["confidence"] == 0.7
    assert body["mitreTechniques"] == ["T1071.001"]
    assert body["affectedHosts"] == ["10.0.0.5"]
    assert body["findings"][0]["title"] == "Beaconing to rare external IP"
    assert body["findings"][0]["severity"] == "high"
    # the trace timeline is built from events (tool_call surfaces; tool_result is
    # merged into it and not a standalone row)
    groups = [s["group"] for s in body["timeline"]]
    titles = [s["title"] for s in body["timeline"]]
    assert "Tool calls" in groups  # the tool_call row
    assert "Objective" in groups  # the hunt_started row
    assert "Findings" in groups  # the hunt_report row
    # the tool_result merged into its tool_call: the row shows the outcome
    assert any("Event search" in t for t in titles)
    # tool_result is not a standalone timeline row
    assert all(s["id"] != "h3" for s in body["timeline"])


def test_get_hunt_not_found(client: TestClient) -> None:
    resp = client.get("/api/v1/hunts/does-not-exist")
    assert resp.status_code == 404


def test_hunt_stats(client: TestClient) -> None:
    _seed_complete_hunt(client)
    resp = client.get("/api/v1/hunts/stats")
    assert resp.status_code == 200
    stats = resp.json()
    labels = {s["label"]: s["value"] for s in stats}
    assert labels["Hunts"] == "1"
    assert labels["Findings"] == "1"
    assert labels["In progress"] == "0"


def _read_hunt(settings: Settings, hunt_id: str) -> dict[str, Any] | None:
    """Read a hunt via an independent engine on the same DB file (sync helper).

    Mirrors test_investigate_tee._read_investigation — the background drainer runs
    on the TestClient's own event loop, so we can't await it from here; instead we
    open a second engine against the same sqlite file and read the persisted row.
    """
    from soc_ai.store.db import make_engine, make_sessionmaker, run_migrations

    async def _go() -> dict[str, Any] | None:
        engine = make_engine(settings)
        await run_migrations(engine)
        maker = make_sessionmaker(engine)
        async with maker() as db:
            got = await hunt_svc.get_with_events(db, hunt_id)
        await engine.dispose()
        if got is None:
            return None
        row, events = got
        return {
            "status": row.status,
            "narrative": row.narrative,
            "report": row.report,
            "kinds": [e.kind for e in events],
        }

    return asyncio.run(_go())


def test_start_hunt_chat_persists_via_manager(
    client: TestClient, settings_kratos: Settings
) -> None:
    """POST /hunts/chat starts a background hunt that lands a complete row.

    Patches the model builder the hunt runner uses so the whole background flow
    runs offline; then polls the persisted row (via an independent engine) until
    the background drainer finalizes it.
    """
    import time

    with patch(
        "soc_ai.api.hunt_runner.build_investigator_model",
        return_value=TestModel(call_tools=[], custom_output_args=FAKE_REPORT),
    ):
        resp = client.post("/api/v1/hunts/chat", json={"objective": "hunt for beaconing"})
        assert resp.status_code == 200
        hunt_id = resp.json()["hunt_id"]

        out: dict[str, Any] | None = None
        for _ in range(50):  # up to ~5s
            out = _read_hunt(settings_kratos, hunt_id)
            if out is not None and out["status"] in ("complete", "error"):
                break
            time.sleep(0.1)

    assert out is not None
    assert out["status"] == "complete"
    assert out["narrative"] == FAKE_REPORT.narrative
    assert out["report"]["confidence"] == 0.7
    assert "hunt_report" in out["kinds"]
    assert "hunt_started" in out["kinds"]


def test_start_hunt_chat_rejects_empty_objective(client: TestClient) -> None:
    resp = client.post("/api/v1/hunts/chat", json={"objective": ""})
    assert resp.status_code == 422  # min_length=1 validation


def test_delete_hunt_removes_row_and_events(client: TestClient, settings_kratos: Settings) -> None:
    """DELETE /hunts/{id} removes a completed hunt and its events; a re-list is empty."""
    hunt_id = _seed_complete_hunt(client)
    # sanity: it's listed
    assert any(r["id"] == hunt_id for r in client.get("/api/v1/hunts").json())

    resp = client.delete(f"/api/v1/hunts/{hunt_id}")
    assert resp.status_code == 200
    assert resp.json() == {"deleted": True}

    # gone from the list AND the detail 404s
    assert all(r["id"] != hunt_id for r in client.get("/api/v1/hunts").json())
    assert client.get(f"/api/v1/hunts/{hunt_id}").status_code == 404


def test_delete_hunt_not_found(client: TestClient) -> None:
    assert client.delete("/api/v1/hunts/does-not-exist").status_code == 404


def test_delete_running_hunt_conflicts(client: TestClient) -> None:
    """A still-running hunt refuses to delete (409) — cancel it first."""

    async def _seed_running() -> str:
        maker = client.app.state.db_sessionmaker
        async with maker() as db:
            hunt = await hunt_svc.create(db, objective="live hunt", started_by="admin")
            return hunt.id  # status defaults to "running", never finalized

    hunt_id = asyncio.run(_seed_running())
    resp = client.delete(f"/api/v1/hunts/{hunt_id}")
    assert resp.status_code == 409
    # still present (not deleted)
    assert client.get(f"/api/v1/hunts/{hunt_id}").status_code == 200


# ── Chat about this hunt (read-only follow-up) ───────────────────────────────


def test_hunt_chat_thread_empty_and_404(client: TestClient) -> None:
    hunt_id = _seed_complete_hunt(client)
    # a completed hunt with no chat yet → empty, not pending
    body = client.get(f"/api/v1/hunts/{hunt_id}/chat").json()
    assert body == {"messages": [], "pending": False}
    # unknown hunt → 404
    assert client.get("/api/v1/hunts/nope/chat").status_code == 404


def test_hunt_chat_rejects_running_hunt(client: TestClient) -> None:
    async def _seed_running() -> str:
        maker = client.app.state.db_sessionmaker
        async with maker() as db:
            hunt = await hunt_svc.create(db, objective="live", started_by="admin")
            return hunt.id

    hunt_id = asyncio.run(_seed_running())
    resp = client.post(f"/api/v1/hunts/{hunt_id}/chat", json={"message": "what did you find?"})
    assert resp.status_code == 409


def test_hunt_chat_rejects_second_turn_while_pending(client: TestClient) -> None:
    """A 2nd POST while a prior turn's assistant is still pending → 409 chat_busy,
    so we never orphan a duplicate pending assistant row."""
    hunt_id = _seed_complete_hunt(client)

    async def _seed_pending() -> None:
        maker = client.app.state.db_sessionmaker
        async with maker() as db:
            await hunt_svc.add_chat_user_message(db, hunt_id, "first question")
            await hunt_svc.create_pending_chat_assistant(db, hunt_id)

    asyncio.run(_seed_pending())
    resp = client.post(f"/api/v1/hunts/{hunt_id}/chat", json={"message": "second"})
    assert resp.status_code == 409
    assert resp.json()["detail"]["reason"] == "chat_busy"


def test_hunt_chat_rejects_empty_message(client: TestClient) -> None:
    hunt_id = _seed_complete_hunt(client)
    # min_length=1 → 422 pydantic validation
    assert client.post(f"/api/v1/hunts/{hunt_id}/chat", json={"message": ""}).status_code == 422


def _read_hunt_chat(settings: Settings, hunt_id: str) -> list[dict[str, Any]]:
    """Read the persisted hunt chat thread via an independent engine on the same DB."""
    from soc_ai.store.db import make_engine, make_sessionmaker, run_migrations

    async def _go() -> list[dict[str, Any]]:
        engine = make_engine(settings)
        await run_migrations(engine)
        maker = make_sessionmaker(engine)
        async with maker() as db:
            msgs = await hunt_svc.list_chat_messages(db, hunt_id)
        await engine.dispose()
        return [{"kind": m.kind, "payload": dict(m.payload or {})} for m in msgs]

    return asyncio.run(_go())


def test_hunt_chat_message_runs_a_turn_and_round_trips(
    client: TestClient, settings_kratos: Settings
) -> None:
    """POST a follow-up on a completed hunt → the background turn lands a done
    assistant answer (mocked model, no live gateway); GET returns the thread."""
    import time

    hunt_id = _seed_complete_hunt(client)

    with patch(
        "soc_ai.webui.hunt_console_manager.build_investigator_model",
        return_value=TestModel(
            call_tools=[], custom_output_text="The rare beacon was to 203.0.113.9."
        ),
    ):
        resp = client.post(
            f"/api/v1/hunts/{hunt_id}/chat",
            json={"message": "which host was beaconing?"},
        )
        assert resp.status_code == 200
        thread = resp.json()
        # the user turn is present immediately; the assistant turn is pending
        assert thread["messages"][0] == {
            "role": "user",
            "text": "which host was beaconing?",
            "tools": None,
        }
        assert thread["pending"] is True

        # poll the persisted thread until the assistant row flips to done
        done: dict[str, Any] | None = None
        for _ in range(50):  # up to ~5s
            rows = _read_hunt_chat(settings_kratos, hunt_id)
            assistant = [r for r in rows if r["kind"] == "chat_assistant"]
            if assistant and assistant[-1]["payload"].get("status") == "done":
                done = assistant[-1]
                break
            time.sleep(0.1)

    assert done is not None
    assert done["payload"]["content"] == "The rare beacon was to 203.0.113.9."

    # GET now returns both turns, not pending
    final = client.get(f"/api/v1/hunts/{hunt_id}/chat").json()
    assert final["pending"] is False
    roles = [m["role"] for m in final["messages"]]
    assert roles == ["user", "assistant"]
    assert final["messages"][1]["text"] == "The rare beacon was to 203.0.113.9."
    # the chat thread must NOT leak into the hunt's execution timeline
    detail = client.get(f"/api/v1/hunts/{hunt_id}").json()
    assert all("chat" not in (s.get("group", "").lower()) for s in detail["timeline"])
    tl_titles = " ".join(s["title"] for s in detail["timeline"])
    assert "which host was beaconing" not in tl_titles


def test_hunt_recorded_run_leads_with_hunt_created(settings_kratos: Settings) -> None:
    """The recorded run emits hunt_created (with the row id) first, then tees the
    agent stream, and finalizes a complete row."""
    engine = None

    async def _go() -> tuple[list[str], str]:
        nonlocal engine
        from soc_ai.store.db import make_engine, make_sessionmaker, run_migrations

        engine = make_engine(settings_kratos)
        await run_migrations(engine)
        maker = make_sessionmaker(engine)
        state = type("S", (), {"db_sessionmaker": maker})()
        names: list[str] = []
        hunt_id = ""
        with patch(
            "soc_ai.api.hunt_runner.build_investigator_model",
            return_value=TestModel(call_tools=[], custom_output_args=FAKE_REPORT),
        ):
            async for name, data in hunt_recorded_run(
                state, ctx=_ctx(settings_kratos), objective="beaconing", started_by="admin"
            ):
                names.append(name)
                if name == "hunt_created":
                    hunt_id = data["hunt_id"]
        # verify the row finalized complete
        async with maker() as db:
            got = await hunt_svc.get_with_events(db, hunt_id)
        assert got is not None
        assert got[0].status == "complete"
        return names, hunt_id

    names, hunt_id = asyncio.run(_go())
    assert names[0] == "hunt_created"
    assert hunt_id
    assert "hunt_report" in names
    asyncio.run(engine.dispose())  # type: ignore[union-attr]
