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
