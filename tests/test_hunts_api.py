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
from datetime import datetime
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
from soc_ai.store.models import Hunt

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
    # Absent-dataset handling: report the visibility gap instead of guessing —
    # and tag it as coverage, never as observed malicious activity.
    assert "A visibility gap is a real result" in p
    assert 'category: "visibility_gap"' in p
    assert "Absence of telemetry is NOT evidence of malicious activity." in p
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


def _dangling_batch_response() -> Any:
    """A ModelResponse ending in an UNEXECUTED tool-call batch — the exact tail a
    budget-exhausted hunt leaves behind (pydantic-ai raises UsageLimitExceeded
    after the response lands in history but before its calls execute; prod
    batches ran ~3 calls)."""
    from pydantic_ai.messages import ModelResponse, TextPart, ToolCallPart

    return ModelResponse(
        parts=[
            TextPart(content="Pivoting: querying three hosts for beacon cadence."),
            ToolCallPart(tool_name="t_query_events_oql", args={"q": "a"}, tool_call_id="c1"),
            ToolCallPart(tool_name="t_query_events_oql", args={"q": "b"}, tool_call_id="c2"),
            ToolCallPart(tool_name="t_query_events_oql", args={"q": "c"}, tool_call_id="c3"),
        ]
    )


def _capturing_synth_model(narrative: str, seen: list[Any]) -> Any:
    """A FunctionModel synthesizer that records the messages it was shown and
    returns a valid HuntReport via the output tool."""
    from pydantic_ai.messages import ModelResponse, ToolCallPart
    from pydantic_ai.models.function import AgentInfo, FunctionModel

    def _fn(messages: list[Any], info: AgentInfo) -> Any:
        seen.append(list(messages))
        return ModelResponse(
            parts=[
                ToolCallPart(
                    tool_name=info.output_tools[0].name,
                    args={"narrative": narrative, "findings": [], "confidence": 0.2},
                )
            ]
        )

    return FunctionModel(_fn)


def test_run_hunt_budget_exhaustion_synthesizes_partial_report(settings_kratos: Settings) -> None:
    """When a hunt exhausts its budget mid-run, the runner synthesizes a PARTIAL
    report from what it gathered instead of erroring with nothing — running the
    REAL ``_synthesize_partial_hunt`` (no mock) against a transcript that ends in
    dangling tool calls, exactly as pydantic-ai leaves it (UsageLimitExceeded is
    raised AFTER the tool-call ModelResponse lands in history but BEFORE the
    calls execute). Pre-fix, the replay died with UserError "Cannot provide a new
    user prompt when the message history contains unprocessed tool calls" and the
    hunt errored — 4/4 prod hunts on 2026-07-08."""
    from types import SimpleNamespace

    from pydantic_ai.exceptions import UsageLimitExceeded
    from pydantic_ai.messages import ModelRequest, ToolReturnPart, UserPromptPart

    class _BudgetRun:
        result = None

        def __init__(self) -> None:
            self._nodes = iter(
                [
                    SimpleNamespace(
                        model_response=None,
                        request=ModelRequest(parts=[UserPromptPart(content="hunt for beaconing")]),
                    ),
                    SimpleNamespace(model_response=_dangling_batch_response(), request=None),
                ]
            )

        async def __aenter__(self) -> _BudgetRun:
            return self

        async def __aexit__(self, *a: Any) -> bool:
            return False

        def __aiter__(self) -> _BudgetRun:
            return self

        async def __anext__(self) -> Any:
            try:
                return next(self._nodes)
            except StopIteration:
                # the batch above was never executed — the budget ran out first
                raise UsageLimitExceeded("tool_calls_limit exceeded") from None

    class _BudgetAgent:
        def iter(self, *a: Any, **k: Any) -> _BudgetRun:
            return _BudgetRun()

    seen: list[Any] = []

    async def _go() -> list[Any]:
        events = []
        with (
            patch("soc_ai.api.hunt_runner.build_hunt_agent", return_value=_BudgetAgent()),
            # The REAL _synthesize_partial_hunt runs; only the model is a double.
            patch(
                "soc_ai.api.hunt_runner.build_investigator_model",
                return_value=_capturing_synth_model("partial — hunt was cut short", seen),
            ),
        ):
            async for ev in run_hunt(_ctx(settings_kratos), objective="hunt for beaconing"):
                events.append(ev)
        return events

    events = asyncio.run(_go())
    kinds = [e.kind for e in events]
    # A report was produced (from real partial synthesis), NOT a bare error.
    assert "hunt_report" in kinds
    assert kinds[-1] == "done"
    assert "error" not in kinds
    report_ev = next(e for e in events if e.kind == "hunt_report")
    assert report_ev.payload["narrative"] == "partial — hunt was cut short"
    # the operator-visible note about the partial synthesis was emitted
    assert any("partial report" in str(e.payload) for e in events)
    # The synthesizer model saw the REPAIRED transcript: one synthetic
    # ToolReturnPart per dangling call, plus the model's final reasoning intact.
    assert len(seen) == 1
    flat_parts = [p for msg in seen[0] for p in msg.parts]
    synthetic = [
        p
        for p in flat_parts
        if isinstance(p, ToolReturnPart) and p.content == "not executed — hunt budget exhausted"
    ]
    assert {p.tool_call_id for p in synthetic} == {"c1", "c2", "c3"}
    assert any(
        getattr(p, "content", None) == "Pivoting: querying three hosts for beacon cadence."
        for p in flat_parts
    )


def test_synthesize_partial_hunt_trims_malformed_tail(settings_kratos: Settings) -> None:
    """Defensive path: a trailing ModelResponse the repair can't read (simulating
    message-class drift after a pydantic-ai bump) is TRIMMED off rather than
    crashing — the synthesizer still lands a partial report from the rest."""
    from pydantic_ai.messages import ModelRequest, ModelResponse, TextPart, UserPromptPart
    from soc_ai.api.hunt_runner import _synthesize_partial_hunt

    # An UN-initialized ModelResponse: isinstance passes but .parts raises.
    malformed = ModelResponse.__new__(ModelResponse)
    gathered: list[Any] = [
        ModelRequest(parts=[UserPromptPart(content="hunt for beaconing")]),
        ModelResponse(parts=[TextPart(content="queried host inventory")]),
        malformed,
    ]

    seen: list[Any] = []
    with patch(
        "soc_ai.api.hunt_runner.build_investigator_model",
        return_value=_capturing_synth_model("partial — tail trimmed", seen),
    ):
        result = asyncio.run(
            _synthesize_partial_hunt(
                _ctx(settings_kratos), objective="hunt for beaconing", gathered=gathered
            )
        )

    assert result.output.narrative == "partial — tail trimmed"
    # The malformed tail was dropped from what the model replayed; the good
    # transcript (and the caller's gathered list) survived intact.
    assert len(seen) == 1
    # identity check — dataclass __eq__ on the un-initialized instance raises
    assert all(m is not malformed for m in seen[0])
    assert gathered[-1] is malformed  # never mutated in place
    flat = [getattr(p, "content", None) for msg in seen[0] for p in msg.parts]
    assert "queried host inventory" in flat


def test_dangling_history_replay_raises_without_repair(settings_kratos: Settings) -> None:
    """Regression anchor for the pre-fix failure mode: replaying a transcript
    that ends in unprocessed tool calls DIRECTLY (no tail repair) is rejected by
    pydantic-ai with UserError — proving ``_repair_dangling_tool_calls`` is what
    saves the partial-report path, not a behavior change in the library."""
    from pydantic_ai.exceptions import UserError
    from pydantic_ai.messages import ModelRequest, UserPromptPart
    from pydantic_ai.usage import UsageLimits
    from soc_ai.agent.hunt import build_hunt_synthesizer

    synth = build_hunt_synthesizer(
        _capturing_synth_model("never reached", []), objective="hunt for beaconing"
    )
    dangling_history: list[Any] = [
        ModelRequest(parts=[UserPromptPart(content="hunt for beaconing")]),
        _dangling_batch_response(),
    ]
    with pytest.raises(UserError, match="unprocessed tool calls"):
        asyncio.run(
            synth.run(
                "Write the HuntReport now from the evidence already gathered above.",
                message_history=dangling_history,
                usage_limits=UsageLimits(request_limit=3, tool_calls_limit=0),
            )
        )


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


def test_finding_category_legacy_inference() -> None:
    """Reports that predate the `category` field: a coverage/visibility finding
    must never surface as a threat (it produced the dishonest "Malicious
    activity found" headline over a telemetry gap)."""
    from soc_ai.api.webui.routes_hunts import _finding_category

    # Explicit categories pass through.
    assert _finding_category({"category": "observation"}) == "observation"
    assert _finding_category({"category": "VISIBILITY_GAP"}) == "visibility_gap"
    # Unknown/missing category: gap-shaped titles infer visibility_gap …
    assert (
        _finding_category(
            {"title": "Critical Visibility Gap: No SMB, RDP, SSH, or Kerberos Telemetry"}
        )
        == "visibility_gap"
    )
    assert _finding_category({"title": "No host process logging on the estate"}) == "visibility_gap"
    # … everything else stays a threat finding (old behavior).
    assert _finding_category({"title": "Beaconing to rare external IP"}) == "threat"


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


def _set_created_at(client: TestClient, hunt_id: str, when: datetime) -> None:
    """Pin a seeded hunt's created_at (server_default=now() at insert)."""

    async def _go() -> None:
        maker = client.app.state.db_sessionmaker
        async with maker() as db:
            row = await db.get(Hunt, hunt_id)
            assert row is not None
            row.created_at = when
            await db.commit()

    asyncio.run(_go())


def test_list_hunts_since_until_filters(client: TestClient) -> None:
    """``since``/``until`` bound created_at inclusively on both ends; a tz-aware
    bound is normalized to the store's naive UTC; no params = original behavior."""
    early = _seed_complete_hunt(client)
    late = _seed_complete_hunt(client)
    _set_created_at(client, early, datetime(2026, 7, 1, 10, 0, 0))
    _set_created_at(client, late, datetime(2026, 7, 3, 10, 0, 0))

    # no params → default behavior unchanged (both rows, newest first)
    rows = client.get("/api/v1/hunts").json()
    assert [r["id"] for r in rows] == [late, early]

    # since alone (inclusive lower bound)
    rows = client.get("/api/v1/hunts", params={"since": "2026-07-02T00:00:00"}).json()
    assert [r["id"] for r in rows] == [late]

    # until alone (inclusive upper bound)
    rows = client.get("/api/v1/hunts", params={"until": "2026-07-02T00:00:00"}).json()
    assert [r["id"] for r in rows] == [early]

    # both bounds — window around the early row only
    rows = client.get(
        "/api/v1/hunts",
        params={"since": "2026-07-01T00:00:00", "until": "2026-07-02T00:00:00"},
    ).json()
    assert [r["id"] for r in rows] == [early]

    # edges landing exactly ON a row keep it — both ends inclusive
    rows = client.get(
        "/api/v1/hunts",
        params={"since": "2026-07-01T10:00:00", "until": "2026-07-01T10:00:00"},
    ).json()
    assert [r["id"] for r in rows] == [early]

    # tz-aware bounds are converted to naive UTC before comparing: 12:00+03:00
    # is 09:00 UTC, so the late row (10:00 UTC that day) is included …
    rows = client.get("/api/v1/hunts", params={"since": "2026-07-03T12:00:00+03:00"}).json()
    assert [r["id"] for r in rows] == [late]
    # … and a Z-suffixed bound works too
    rows = client.get("/api/v1/hunts", params={"since": "2026-07-02T00:00:00Z"}).json()
    assert [r["id"] for r in rows] == [late]


def test_list_hunts_invalid_datetime_is_422(client: TestClient) -> None:
    assert client.get("/api/v1/hunts", params={"since": "not-a-datetime"}).status_code == 422
    assert client.get("/api/v1/hunts", params={"until": "yesterday-ish"}).status_code == 422


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


def test_hunt_console_manager_caps_concurrent_hunts() -> None:
    """HuntConsoleManager.start() returns None once its shared concurrency ceiling
    is reached, so a rapid-fire burst of POST /hunts/chat (or a large bulk re-hunt
    / schedule storm) can't put unbounded simultaneous hunts on the single model
    route — the documented 7-concurrent-hunts incident. Slots free up as hunts
    finish, and every start()-driven path (ad-hoc, bulk, scheduled) shares it."""
    from unittest.mock import MagicMock

    from soc_ai.webui import hunt_console_manager as hcm

    async def _go() -> None:
        # An asyncio.Event held OPEN keeps each background drain task in flight so
        # the manager's in-flight count stays at the ceiling for the test.
        block = asyncio.Event()
        counter = {"n": 0}

        def _fake_run(_state: Any, **_kw: Any) -> Any:
            counter["n"] += 1
            hid = f"h{counter['n']}"

            async def _gen() -> Any:
                yield "hunt_created", {"hunt_id": hid}
                await block.wait()  # hold the drain open until released

            return _gen()

        mgr = hcm.HuntConsoleManager()
        with (
            patch.object(hcm, "hunt_recorded_run", _fake_run),
            patch.object(hcm, "ctx_from_state", lambda _s: MagicMock()),
        ):
            n_attempts = 12  # more than any sane ceiling
            results = [
                await mgr.start(MagicMock(), objective="o", started_by="t")
                for _ in range(n_attempts)
            ]
            started = [r for r in results if r is not None]
            # An unguarded manager starts ALL of them; the guard must bound it.
            assert 0 < len(started) < n_attempts
            # ...and the bound is exactly the shared ceiling.
            assert len(started) == hcm._MAX_CONCURRENT_HUNTS
            # Rejections come AFTER the ceiling (deferral, not a random scramble).
            assert results[: len(started)] == started
            assert all(r is None for r in results[len(started) :])

            # Release the in-flight hunts; their tasks finish and free their slots.
            block.set()
            await asyncio.gather(*list(mgr._tasks.values()))
            for _ in range(5):
                await asyncio.sleep(0)  # flush done-callbacks (slot cleanup)
            assert not mgr._tasks
            # A slot is available again → a fresh start succeeds.
            assert await mgr.start(MagicMock(), objective="o", started_by="t") is not None
            await asyncio.gather(*list(mgr._tasks.values()))

    asyncio.run(_go())


def test_run_hunt_chat_turn_error_content_is_scrubbed_before_persisting() -> None:
    """F75: identical to the investigation-chat catch-all (chat_manager.py) —
    the raised exception's message is stringified straight into the persisted
    error content. A verbose provider/gateway error body echoing a credential
    must be scrubbed, not stored/rendered verbatim."""
    from unittest.mock import MagicMock

    from soc_ai.webui import hunt_console_manager as hcm

    hunt = MagicMock()
    hunt.id = "hunt-secret"
    hunt.objective = "hunt for beaconing"
    hunt.narrative = "nothing yet"
    hunt.report = {}

    finish_mock = AsyncMock()

    db = AsyncMock()
    db_cm = MagicMock()
    db_cm.__aenter__ = AsyncMock(return_value=db)
    db_cm.__aexit__ = AsyncMock(return_value=False)

    settings = MagicMock()
    settings.soc_ai_demo = False
    settings.analyst_cloud_redaction = False
    settings.hunt_chat_turn_timeout_s = 180

    state = MagicMock()
    state.settings = settings
    state.db_sessionmaker = MagicMock(return_value=db_cm)

    _get_with_events = AsyncMock(return_value=(hunt, []))
    _history = AsyncMock(return_value=[("user", "which host?")])

    secret_token = "sk-live-abc123SECRET"  # pragma: allowlist secret

    with (
        patch.object(hcm.hunt_svc, "get_with_events", _get_with_events),
        patch.object(hcm.hunt_svc, "chat_history_for_agent", _history),
        patch.object(hcm.hunt_svc, "finish_chat_assistant", finish_mock),
        patch.object(hcm, "build_chat_agent") as mock_build,
        patch.object(hcm, "build_investigator_model", MagicMock()),
    ):
        agent_mock = MagicMock()
        agent_mock.run = AsyncMock(
            side_effect=RuntimeError(f"gateway 401: Authorization: Bearer {secret_token}")
        )
        mock_build.return_value = agent_mock

        asyncio.run(hcm._run_hunt_chat_turn(state, "hunt-secret", 42))

    finish_mock.assert_called_once()
    content = finish_mock.call_args.kwargs.get("content", "")
    assert secret_token not in content
    assert finish_mock.call_args.kwargs.get("status") == "error"


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


# ── E1.3: post-hunt citation gate ────────────────────────────────────────────


def _tool_result(result: Any) -> dict[str, Any]:
    """A canned tool_result event payload's ``result`` value (the shape the hunt
    citation gate consumes — the JSON the hunt actually pulled)."""
    return result


def test_validate_hunt_findings_strips_fabricated_citation() -> None:
    """A finding citing an id that appears in NO gathered tool result → the
    non-resolving citations are stripped, severity capped to low, note set."""
    from soc_ai.agent.hunt_gates import _validate_hunt_findings

    findings = [
        HuntFinding(
            title="Beaconing to rare external IP",
            detail="A host beacons on a 60s cadence.",
            severity="high",
            hosts=["10.0.0.5"],
            citations=["sFABRICATED_ID_9xQ"],  # never pulled
        )
    ]
    # The hunt pulled a zeek hit with a totally different id.
    tool_results = [
        _tool_result({"total": 1, "hits": [{"_id": "sREAL_PULLED_ID_42", "dataset": "zeek.conn"}]})
    ]

    validated, counts = _validate_hunt_findings(findings, tool_results)

    assert len(validated) == 1
    f = validated[0]
    assert f.citations == []  # fabricated citation stripped
    assert f.severity == "low"  # capped down from high
    assert f.validator_note is not None
    assert "did not resolve" in f.validator_note.lower()
    assert counts["findings_capped"] == 1
    assert counts["citations_stripped"] == 1


def test_validate_hunt_findings_keeps_resolving_citation() -> None:
    """A finding citing a real gathered id → unchanged (severity, citations, no note)."""
    from soc_ai.agent.hunt_gates import _validate_hunt_findings

    findings = [
        HuntFinding(
            title="Beaconing to rare external IP",
            detail="A host beacons on a 60s cadence.",
            severity="high",
            hosts=["10.0.0.5"],
            citations=["sREAL_PULLED_ID_42"],
        )
    ]
    tool_results = [
        _tool_result({"total": 1, "hits": [{"_id": "sREAL_PULLED_ID_42", "dataset": "zeek.conn"}]})
    ]

    validated, counts = _validate_hunt_findings(findings, tool_results)

    f = validated[0]
    assert f.citations == ["sREAL_PULLED_ID_42"]  # unchanged
    assert f.severity == "high"  # NOT capped
    assert f.validator_note is None
    assert counts["findings_capped"] == 0
    assert counts["citations_stripped"] == 0


def test_validate_hunt_findings_high_sev_no_citations_capped() -> None:
    """A high-severity finding with an EMPTY citations list → capped to medium + noted
    (an empty-citation observation is otherwise left alone)."""
    from soc_ai.agent.hunt_gates import _validate_hunt_findings

    findings = [
        HuntFinding(
            title="Suspicious lateral movement",
            detail="Cross-host SMB writes observed.",
            severity="critical",
            hosts=["10.0.0.9"],
            citations=[],
        ),
        HuntFinding(
            title="Benign context",
            detail="An informational observation.",
            severity="info",
            citations=[],
        ),
    ]
    validated, counts = _validate_hunt_findings(findings, [])

    high = validated[0]
    assert high.severity == "medium"  # critical capped to medium
    assert high.validator_note is not None
    assert "lacks citations" in high.validator_note.lower()
    # the info observation with no citations is untouched
    low = validated[1]
    assert low.severity == "info"
    assert low.validator_note is None
    assert counts["findings_capped"] == 1


def test_validate_hunt_findings_clamps_overlong_title() -> None:
    """An overlong machine-generated title (> 90 chars) is word-boundary truncated
    with a trailing ellipsis; a compliant title passes through untouched."""
    from soc_ai.agent.hunt_gates import _validate_hunt_findings

    long_title = (
        "Sustained periodic beaconing from an internal workstation to a rare external "
        "IP with low data volume and a highly regular sixty-second cadence"
    )
    assert len(long_title) > 90
    findings = [
        HuntFinding(title=long_title, detail="A host beacons on a 60s cadence."),
        HuntFinding(title="Beaconing to rare external IP", detail="Compliant title."),
    ]
    validated, _ = _validate_hunt_findings(findings, [])

    clamped = validated[0].title
    assert len(clamped) <= 90
    assert clamped.endswith("…")
    # cut on a word boundary: the kept text is a prefix of the original that
    # ended exactly at a space (no mid-word chop)
    kept = clamped[:-1]
    assert long_title.startswith(kept)
    assert long_title[len(kept)] == " "
    # compliant title untouched
    assert validated[1].title == "Beaconing to rare external IP"


def test_validate_hunt_findings_clamps_unbroken_title() -> None:
    """A single overlong token (no word boundary to cut at) is hard-cut to the
    ceiling rather than left to overflow."""
    from soc_ai.agent.hunt_gates import _validate_hunt_findings

    findings = [HuntFinding(title="x" * 200, detail="d")]
    validated, _ = _validate_hunt_findings(findings, [])
    assert len(validated[0].title) <= 90
    assert validated[0].title.endswith("…")


def test_run_hunt_gate_strips_fabricated_citation_end_to_end(settings_kratos: Settings) -> None:
    """Drive run_hunt with a report citing an id NOT in the streamed tool_result:
    the emitted hunt_report has the citation stripped + severity capped, and a
    citation_validation event is emitted before it."""
    from types import SimpleNamespace

    from pydantic_ai.messages import ModelResponse, ToolCallPart, ToolReturnPart

    # One tool_result the hunt actually pulled (a real id), then a report that
    # cites a DIFFERENT (fabricated) id.
    real_id = "sREAL_PULLED_ID_42"
    report = HuntReport(
        findings=[
            HuntFinding(
                title="Beaconing to rare external IP",
                detail="A host beacons on a 60s cadence.",
                severity="high",
                hosts=["10.0.0.5"],
                citations=["sFABRICATED_9xQ"],  # never pulled
            )
        ],
        narrative="One host is beaconing.",
        affected_hosts=["10.0.0.5"],
        confidence=0.7,
    )

    class _Run:
        def __init__(self) -> None:
            self._nodes = iter(
                [
                    # a tool_call node then a tool_result node carrying the real id
                    SimpleNamespace(
                        model_response=ModelResponse(
                            parts=[
                                ToolCallPart(
                                    tool_name="t_query_events_oql", args={}, tool_call_id="c1"
                                )
                            ]
                        ),
                        request=None,
                    ),
                    SimpleNamespace(
                        model_response=None,
                        request=SimpleNamespace(
                            parts=[
                                ToolReturnPart(
                                    tool_name="t_query_events_oql",
                                    content={"total": 1, "hits": [{"_id": real_id}]},
                                    tool_call_id="c1",
                                )
                            ]
                        ),
                    ),
                ]
            )
            self.result = SimpleNamespace(output=report)

        async def __aenter__(self) -> _Run:
            return self

        async def __aexit__(self, *a: Any) -> bool:
            return False

        def __aiter__(self) -> _Run:
            return self

        async def __anext__(self) -> Any:
            try:
                return next(self._nodes)
            except StopIteration:
                raise StopAsyncIteration from None

    class _Agent:
        def iter(self, *a: Any, **k: Any) -> _Run:
            return _Run()

    async def _go() -> list[Any]:
        events = []
        with (
            patch("soc_ai.api.hunt_runner.build_hunt_agent", return_value=_Agent()),
            patch(
                "soc_ai.api.hunt_runner.build_investigator_model",
                return_value=TestModel(call_tools=[]),
            ),
        ):
            async for ev in run_hunt(_ctx(settings_kratos), objective="hunt for beaconing"):
                events.append(ev)
        return events

    events = asyncio.run(_go())
    kinds = [e.kind for e in events]
    # the gate emitted its per-hunt count, before the report
    assert "citation_validation" in kinds
    assert kinds.index("citation_validation") < kinds.index("hunt_report")
    cv = next(e for e in events if e.kind == "citation_validation")
    assert cv.payload["findings_capped"] == 1
    assert cv.payload["citations_stripped"] == 1
    # the report finding was stripped + capped
    report_ev = next(e for e in events if e.kind == "hunt_report")
    f = report_ev.payload["findings"][0]
    assert f["citations"] == []
    assert f["severity"] == "low"
    assert "did not resolve" in (f["validator_note"] or "").lower()


def test_hunt_detail_serializes_validator_note(client: TestClient) -> None:
    """A stored finding carrying validator_note surfaces as validatorNote on the
    hunt detail response (the FE reads it to render the post-validator note)."""

    async def _seed() -> str:
        maker = client.app.state.db_sessionmaker
        report = HuntReport(
            findings=[
                HuntFinding(
                    title="Beaconing to rare external IP",
                    detail="A host beacons on a 60s cadence.",
                    severity="low",
                    hosts=["10.0.0.5"],
                    citations=[],
                    validator_note="Citations did not resolve to gathered evidence; "
                    "severity capped to low.",
                )
            ],
            narrative="One host beaconed; the citation did not resolve.",
            affected_hosts=["10.0.0.5"],
            confidence=0.4,
        )
        async with maker() as db:
            hunt = await hunt_svc.create(db, objective="hunt for beaconing", started_by="admin")
            await hunt_svc.finalize(
                db,
                hunt.id,
                status="complete",
                narrative=report.narrative,
                report=report.model_dump(mode="json"),
            )
            return hunt.id

    hunt_id = asyncio.run(_seed())
    body = client.get(f"/api/v1/hunts/{hunt_id}").json()
    assert body["findings"][0]["severity"] == "low"
    assert body["findings"][0]["validatorNote"]
    assert "did not resolve" in body["findings"][0]["validatorNote"].lower()


# ── E3.3: agent-authored charts (post-hunt chart gate) ───────────────────────


def _chart(**kw: Any) -> Any:
    from soc_ai.agent.hunt import HuntChart, HuntChartPoint

    kw.setdefault("kind", "bar")
    kw.setdefault("title", "Beacon interval histogram")
    series = kw.pop("series", [("60s", 12.0), ("120s", 3.0)])
    return HuntChart(series=[HuntChartPoint(x=x, y=y) for x, y in series], **kw)


def test_hunt_report_charts_round_trip() -> None:
    """HuntReport with charts serializes + re-validates through the schema."""
    from soc_ai.agent.hunt import HuntChart, HuntChartPoint

    report = HuntReport(
        narrative="one beaconing host",
        charts=[
            HuntChart(
                kind="bar",
                title="Beacon interval histogram",
                x_label="interval",
                y_label="count",
                series=[HuntChartPoint(x="60s", y=12.0), HuntChartPoint(x="120s", y=3.0)],
                source_citations=["sREAL_PULLED_ID_42"],
            )
        ],
    )
    dumped = report.model_dump(mode="json")
    assert dumped["charts"][0]["kind"] == "bar"
    assert dumped["charts"][0]["series"][0] == {"x": "60s", "y": 12.0}
    # round-trips back into the model unchanged
    again = HuntReport.model_validate(dumped)
    assert again.charts[0].source_citations == ["sREAL_PULLED_ID_42"]
    # defaults: no charts on a bare report
    assert HuntReport(narrative="x").charts == []


def test_validate_hunt_charts_keeps_resolving_chart() -> None:
    """A chart whose source_citations resolve to a gathered tool result SURVIVES."""
    from soc_ai.agent.hunt_gates import _validate_hunt_charts

    charts = [_chart(source_citations=["sREAL_PULLED_ID_42"])]
    tool_results = [
        _tool_result({"total": 1, "hits": [{"_id": "sREAL_PULLED_ID_42", "dataset": "zeek.conn"}]})
    ]
    kept, counts = _validate_hunt_charts(charts, tool_results)
    assert len(kept) == 1
    assert counts["charts"] == 1
    assert counts["charts_dropped"] == 0


def test_validate_hunt_charts_drops_fabricated_chart() -> None:
    """A chart citing an id that appears in NO gathered tool result is DROPPED."""
    from soc_ai.agent.hunt_gates import _validate_hunt_charts

    charts = [_chart(source_citations=["sFABRICATED_ID_9xQ"])]
    tool_results = [
        _tool_result({"total": 1, "hits": [{"_id": "sREAL_PULLED_ID_42", "dataset": "zeek.conn"}]})
    ]
    kept, counts = _validate_hunt_charts(charts, tool_results)
    assert kept == []
    assert counts["charts_dropped"] == 1


def test_validate_hunt_charts_drops_empty_or_uncited() -> None:
    """A chart with no source_citations, or no series, is DROPPED (can't be traced)."""
    from soc_ai.agent.hunt_gates import _validate_hunt_charts

    tool_results = [_tool_result({"hits": [{"_id": "sREAL_PULLED_ID_42"}]})]
    # no citations at all
    kept, counts = _validate_hunt_charts([_chart(source_citations=[])], tool_results)
    assert kept == []
    assert counts["charts_dropped"] == 1
    # empty series (nothing to plot), even with a resolving citation
    kept2, counts2 = _validate_hunt_charts(
        [_chart(series=[], source_citations=["sREAL_PULLED_ID_42"])], tool_results
    )
    assert kept2 == []
    assert counts2["charts_dropped"] == 1


def test_validate_hunt_charts_caps_at_four() -> None:
    """Beyond four charts, extras are dropped even when they'd otherwise resolve."""
    from soc_ai.agent.hunt_gates import _validate_hunt_charts

    tool_results = [_tool_result({"hits": [{"_id": "sREAL_PULLED_ID_42"}]})]
    charts = [_chart(title=f"c{i}", source_citations=["sREAL_PULLED_ID_42"]) for i in range(6)]
    kept, counts = _validate_hunt_charts(charts, tool_results)
    assert len(kept) == 4
    assert counts["charts_dropped"] == 2


def test_validate_hunt_charts_clamps_overlong_title() -> None:
    """A kept chart's overlong title gets the same word-boundary clamp as findings."""
    from soc_ai.agent.hunt_gates import _validate_hunt_charts

    long_title = (
        "Distribution of beacon intervals observed between the internal workstation "
        "and the rare external destination over the whole lookback window"
    )
    assert len(long_title) > 90
    tool_results = [_tool_result({"hits": [{"_id": "sREAL_PULLED_ID_42"}]})]
    charts = [_chart(title=long_title, source_citations=["sREAL_PULLED_ID_42"])]
    kept, _ = _validate_hunt_charts(charts, tool_results)
    assert len(kept) == 1
    assert len(kept[0].title) <= 90
    assert kept[0].title.endswith("…")
    assert long_title.startswith(kept[0].title[:-1])


def test_run_hunt_chart_gate_end_to_end(settings_kratos: Settings) -> None:
    """Drive run_hunt with a report carrying ONE resolving chart + ONE fabricated
    chart: the emitted hunt_report keeps only the resolving one, and the
    citation_validation event carries the charts/charts_dropped counts."""
    from types import SimpleNamespace

    from pydantic_ai.messages import ModelResponse, ToolCallPart, ToolReturnPart
    from soc_ai.agent.hunt import HuntChart, HuntChartPoint

    real_id = "sREAL_PULLED_ID_42"
    report = HuntReport(
        findings=[],
        narrative="one beaconing host",
        affected_hosts=["10.0.0.5"],
        confidence=0.6,
        charts=[
            HuntChart(
                kind="bar",
                title="Beacon interval histogram",
                series=[HuntChartPoint(x="60s", y=12.0)],
                source_citations=[real_id],  # resolves
            ),
            HuntChart(
                kind="line",
                title="Invented bytes-over-time",
                series=[HuntChartPoint(x="t0", y=1.0)],
                source_citations=["sFABRICATED_9xQ"],  # never pulled → dropped
            ),
        ],
    )

    class _Run:
        def __init__(self) -> None:
            self._nodes = iter(
                [
                    SimpleNamespace(
                        model_response=ModelResponse(
                            parts=[
                                ToolCallPart(
                                    tool_name="t_query_events_oql", args={}, tool_call_id="c1"
                                )
                            ]
                        ),
                        request=None,
                    ),
                    SimpleNamespace(
                        model_response=None,
                        request=SimpleNamespace(
                            parts=[
                                ToolReturnPart(
                                    tool_name="t_query_events_oql",
                                    content={"total": 1, "hits": [{"_id": real_id}]},
                                    tool_call_id="c1",
                                )
                            ]
                        ),
                    ),
                ]
            )
            self.result = SimpleNamespace(output=report)

        async def __aenter__(self) -> _Run:
            return self

        async def __aexit__(self, *a: Any) -> bool:
            return False

        def __aiter__(self) -> _Run:
            return self

        async def __anext__(self) -> Any:
            try:
                return next(self._nodes)
            except StopIteration:
                raise StopAsyncIteration from None

    class _Agent:
        def iter(self, *a: Any, **k: Any) -> _Run:
            return _Run()

    async def _go() -> list[Any]:
        events = []
        with (
            patch("soc_ai.api.hunt_runner.build_hunt_agent", return_value=_Agent()),
            patch(
                "soc_ai.api.hunt_runner.build_investigator_model",
                return_value=TestModel(call_tools=[]),
            ),
        ):
            async for ev in run_hunt(_ctx(settings_kratos), objective="hunt for beaconing"):
                events.append(ev)
        return events

    events = asyncio.run(_go())
    cv = next(e for e in events if e.kind == "citation_validation")
    assert cv.payload["charts"] == 2
    assert cv.payload["charts_dropped"] == 1
    report_ev = next(e for e in events if e.kind == "hunt_report")
    charts = report_ev.payload["charts"]
    assert len(charts) == 1  # only the resolving chart survived
    assert charts[0]["title"] == "Beacon interval histogram"
    assert charts[0]["source_citations"] == [real_id]


def test_hunt_detail_serializes_accepted_charts(client: TestClient) -> None:
    """A stored report's charts surface (camelCased) on the hunt detail response;
    a malformed/empty-series chart is dropped by the serializer."""

    async def _seed() -> str:
        maker = client.app.state.db_sessionmaker
        report = HuntReport(
            findings=[],
            narrative="one beaconing host",
            affected_hosts=["10.0.0.5"],
            confidence=0.6,
        )
        payload = report.model_dump(mode="json")
        # a good chart + a junk one the serializer should drop (empty series)
        payload["charts"] = [
            {
                "kind": "bar",
                "title": "Beacon interval histogram",
                "x_label": "interval",
                "y_label": "count",
                "series": [{"x": "60s", "y": 12.0}, {"x": "120s", "y": 3.0}],
                "source_citations": ["sREAL_PULLED_ID_42"],
            },
            {"kind": "line", "title": "empty", "series": [], "source_citations": ["x"]},
        ]
        async with maker() as db:
            hunt = await hunt_svc.create(db, objective="hunt for beaconing", started_by="admin")
            await hunt_svc.finalize(
                db,
                hunt.id,
                status="complete",
                narrative=report.narrative,
                report=payload,
            )
            return hunt.id

    hunt_id = asyncio.run(_seed())
    body = client.get(f"/api/v1/hunts/{hunt_id}").json()
    assert len(body["charts"]) == 1  # the empty-series chart was dropped
    chart = body["charts"][0]
    assert chart["kind"] == "bar"
    assert chart["title"] == "Beacon interval histogram"
    assert chart["xLabel"] == "interval"
    assert chart["yLabel"] == "count"
    assert chart["series"][0] == {"x": "60s", "y": 12.0}
    assert chart["sourceCitations"] == ["sREAL_PULLED_ID_42"]


# ── E3.4: hunt diffing (objective_hash + previous_completed_run + GET diff) ───


def test_objective_hash_stable_and_normalized() -> None:
    """_objective_hash is stable + case/whitespace-insensitive so re-runs link."""
    from soc_ai.store.hunts import _objective_hash

    base = _objective_hash("Hunt for beaconing")
    # identical input → identical hash (stable)
    assert base == _objective_hash("Hunt for beaconing")
    # case-insensitive
    assert base == _objective_hash("hunt for beaconing")
    # whitespace-collapsed + trimmed (leading/trailing/internal runs, newlines/tabs)
    assert base == _objective_hash("  hunt   for\tbeaconing\n")
    # a genuinely different objective does NOT collide
    assert base != _objective_hash("hunt for lateral movement")
    # fits the indexed String(64) column
    assert len(base) <= 64


def _seed_hunt_at(
    client: TestClient,
    *,
    objective: str,
    status: str,
    findings: list[HuntFinding],
    created_at: datetime,
) -> str:
    """Insert a hunt with an explicit created_at + a report of the given findings."""
    from soc_ai.store.models import Hunt

    report = HuntReport(
        findings=findings,
        narrative="seeded",
        affected_hosts=sorted({h for f in findings for h in f.hosts}),
        confidence=0.5,
    )

    async def _go() -> str:
        maker = client.app.state.db_sessionmaker
        async with maker() as db:
            hunt = await hunt_svc.create(db, objective=objective, started_by="admin")
            # Pin created_at for deterministic ordering + finalize the report.
            row = await db.get(Hunt, hunt.id)
            assert row is not None
            row.created_at = created_at
            await db.commit()
            if status == "complete":
                await hunt_svc.finalize(
                    db,
                    hunt.id,
                    status="complete",
                    narrative=report.narrative,
                    report=report.model_dump(mode="json"),
                )
            return hunt.id

    return asyncio.run(_go())


def _finding(title: str, host: str, severity: str = "medium") -> HuntFinding:
    return HuntFinding(title=title, detail="d", severity=severity, hosts=[host], citations=[])


def test_previous_completed_run_finds_prior_same_objective(
    client: TestClient, settings_kratos: Settings
) -> None:
    """previous_completed_run returns the prior COMPLETE run with the same hash;
    NOT a different-objective run, NOT the current hunt, NOT a running run."""
    from datetime import timedelta

    from soc_ai.store.models import Hunt

    t0 = datetime(2026, 7, 7, 12, 0, 0)
    prior = _seed_hunt_at(
        client,
        objective="hunt for beaconing",
        status="complete",
        findings=[_finding("A", "10.0.0.1")],
        created_at=t0,
    )
    # a DIFFERENT objective (different hash) — must be ignored
    _seed_hunt_at(
        client,
        objective="hunt for lateral movement",
        status="complete",
        findings=[_finding("X", "10.0.0.9")],
        created_at=t0 + timedelta(minutes=1),
    )
    # a RUNNING run of the same objective — must be ignored (not complete)
    _seed_hunt_at(
        client,
        objective="Hunt for Beaconing",  # same normalized hash
        status="running",
        findings=[],
        created_at=t0 + timedelta(minutes=2),
    )
    current = _seed_hunt_at(
        client,
        objective="hunt for beaconing",
        status="complete",
        findings=[_finding("A", "10.0.0.1")],
        created_at=t0 + timedelta(minutes=5),
    )

    async def _go() -> str | None:
        maker = client.app.state.db_sessionmaker
        async with maker() as db:
            cur = await db.get(Hunt, current)
            assert cur is not None
            prev = await hunt_svc.previous_completed_run(
                db,
                objective_hash=cur.objective_hash,
                before_created_at=cur.created_at,
                exclude_id=cur.id,
            )
            return prev.id if prev is not None else None

    assert asyncio.run(_go()) == prior


def test_previous_completed_run_none_when_first_run(
    client: TestClient, settings_kratos: Settings
) -> None:
    """The first run of an objective has no prior COMPLETE run → None."""
    from soc_ai.store.models import Hunt

    only = _seed_hunt_at(
        client,
        objective="hunt for beaconing",
        status="complete",
        findings=[_finding("A", "10.0.0.1")],
        created_at=datetime(2026, 7, 7, 12, 0, 0),
    )

    async def _go() -> str | None:
        maker = client.app.state.db_sessionmaker
        async with maker() as db:
            cur = await db.get(Hunt, only)
            assert cur is not None
            prev = await hunt_svc.previous_completed_run(
                db,
                objective_hash=cur.objective_hash,
                before_created_at=cur.created_at,
                exclude_id=cur.id,
            )
            return prev.id if prev is not None else None

    assert asyncio.run(_go()) is None


def test_get_hunt_diff_new_persisting_resolved(
    client: TestClient, settings_kratos: Settings
) -> None:
    """End-to-end via GET /hunts/{id}: seed a prior complete hunt (findings A,B,C)
    + a later complete hunt same objective (findings A,B,D) → diff = 1 new (D) ·
    2 persisting (A,B) · 1 resolved (C)."""
    from datetime import timedelta

    t0 = datetime(2026, 7, 7, 12, 0, 0)
    _seed_hunt_at(
        client,
        objective="hunt for beaconing",
        status="complete",
        findings=[
            _finding("Finding A", "10.0.0.1"),
            _finding("Finding B", "10.0.0.2"),
            _finding("Finding C", "10.0.0.3"),
        ],
        created_at=t0,
    )
    current = _seed_hunt_at(
        client,
        objective="hunt for beaconing",
        status="complete",
        findings=[
            _finding("Finding A", "10.0.0.1"),  # persisting
            _finding("Finding B", "10.0.0.2"),  # persisting
            _finding("Finding D", "10.0.0.4"),  # new
        ],
        created_at=t0 + timedelta(minutes=5),
    )

    body = client.get(f"/api/v1/hunts/{current}").json()
    diff = body["diff"]
    assert diff is not None
    assert sorted(e["title"] for e in diff["new"]) == ["Finding D"]
    assert sorted(e["title"] for e in diff["persisting"]) == ["Finding A", "Finding B"]
    assert sorted(e["title"] for e in diff["resolved"]) == ["Finding C"]
    # the baseline run is referenced (for the "vs run from {ago}" label)
    assert diff["previousHuntId"]
    assert diff["previousTs"]


def test_get_hunt_diff_absent_on_first_run(client: TestClient, settings_kratos: Settings) -> None:
    """A hunt with no prior completed run of its objective has diff == None."""
    only = _seed_hunt_at(
        client,
        objective="hunt for beaconing",
        status="complete",
        findings=[_finding("Finding A", "10.0.0.1")],
        created_at=datetime(2026, 7, 7, 12, 0, 0),
    )
    body = client.get(f"/api/v1/hunts/{only}").json()
    assert body["diff"] is None


def test_get_hunt_diff_fuzzy_title_and_hosts_identity(
    client: TestClient, settings_kratos: Settings
) -> None:
    """Finding identity is fuzzy on (normalized title + hosts set): case/
    punctuation/whitespace + host order don't matter, but distinct hosts do."""
    from datetime import timedelta

    t0 = datetime(2026, 7, 7, 12, 0, 0)
    _seed_hunt_at(
        client,
        objective="hunt for beaconing",
        status="complete",
        findings=[
            HuntFinding(
                title="Beaconing to rare external IP",
                detail="d",
                severity="high",
                hosts=["10.0.0.1", "10.0.0.2"],
                citations=[],
            ),
        ],
        created_at=t0,
    )
    current = _seed_hunt_at(
        client,
        objective="hunt for beaconing",
        status="complete",
        findings=[
            # same finding, re-worded punctuation/case + reversed host order → persisting
            HuntFinding(
                title="beaconing to rare, external IP.",
                detail="d",
                severity="high",
                hosts=["10.0.0.2", "10.0.0.1"],
                citations=[],
            ),
        ],
        created_at=t0 + timedelta(minutes=5),
    )
    diff = client.get(f"/api/v1/hunts/{current}").json()["diff"]
    assert len(diff["persisting"]) == 1
    assert diff["new"] == []
    assert diff["resolved"] == []


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


# ── Corroboration gate: a high threat citing ONLY detector alerts is capped ──


def _labeled(tool_name: str, result: Any) -> dict[str, Any]:
    """A labeled gathered-evidence item, the shape hunt_runner now collects
    ({tool_name, result}) so the corroboration gate can classify a citation's
    source tool."""
    return {"tool_name": tool_name, "result": result}


def test_validate_hunt_findings_caps_high_threat_citing_only_alerts() -> None:
    """The core trust-erosion fix: a high-severity THREAT finding whose only
    resolving citation lands in an alert-query result (t_query_events_oql on the
    suricata.alert doc that IS the claim) is capped to medium with the
    corroborate-first note — even though the cited id genuinely exists."""
    from soc_ai.agent.hunt_gates import _validate_hunt_findings

    findings = [
        HuntFinding(
            title="BPFDoor backdoor on 192.0.2.15",
            detail="An ICMP heartbeat alert matched the BPFDoor signature.",
            severity="high",
            category="threat",
            hosts=["192.0.2.15"],
            citations=["sALERT_DOC_7Zk"],  # the alert that IS the claim
        )
    ]
    # The ONLY gathered evidence is the alert document itself (an alert-query tool).
    tool_results = [
        _labeled(
            "t_query_events_oql",
            {
                "total": 1,
                "hits": [
                    {"_id": "sALERT_DOC_7Zk", "rule.name": "ET MALWARE BPFDoor ICMP heartbeat"}
                ],
            },
        )
    ]

    validated, counts = _validate_hunt_findings(findings, tool_results)

    f = validated[0]
    assert f.severity == "medium"  # capped from high — cited only the alert
    assert f.citations == ["sALERT_DOC_7Zk"]  # citation still resolves (it exists)
    assert f.validator_note is not None
    assert "only detector alerts cited" in f.validator_note.lower()
    assert counts["findings_capped"] == 1
    # the citation resolved, so nothing was stripped
    assert counts["citations_stripped"] == 0


def test_validate_hunt_findings_high_threat_with_corroboration_stays_high() -> None:
    """The SAME finding, but also citing a t_get_pcap (corroborating) result →
    stays HIGH. Corroboration beyond the detector alert is exactly what unlocks
    the severity."""
    from soc_ai.agent.hunt_gates import _validate_hunt_findings

    findings = [
        HuntFinding(
            title="Confirmed C2 beacon on 10.0.0.5",
            detail="Alert plus a measured 60s beacon cadence in the pcap.",
            severity="high",
            category="threat",
            hosts=["10.0.0.5"],
            citations=["sALERT_DOC_7Zk", "sPCAP_EVIDENCE_9Qm"],
        )
    ]
    tool_results = [
        _labeled(
            "t_query_events_oql",
            {"total": 1, "hits": [{"_id": "sALERT_DOC_7Zk", "rule.name": "ET HUNTING beacon"}]},
        ),
        _labeled(
            "t_get_pcap",
            {"beacon": {"interval_s": 60, "jitter": 0.02}, "marker": "sPCAP_EVIDENCE_9Qm"},
        ),
    ]

    validated, counts = _validate_hunt_findings(findings, tool_results)

    f = validated[0]
    assert f.severity == "high"  # NOT capped — corroborated by the pcap
    assert f.validator_note is None
    assert counts["findings_capped"] == 0


def test_validate_hunt_findings_corroboration_only_applies_to_high_threat() -> None:
    """A MEDIUM threat, and a HIGH non-threat (observation), citing only an alert
    result are BOTH left alone — the corroboration cap targets only the loud
    high/critical threat write-up."""
    from soc_ai.agent.hunt_gates import _validate_hunt_findings

    findings = [
        HuntFinding(
            title="Rule fired on internal ICMP",
            detail="A heartbeat rule fired; noted for context.",
            severity="medium",
            category="threat",
            citations=["sALERT_DOC_7Zk"],
        ),
        HuntFinding(
            title="High-volume informational alerting",
            detail="This grid alerts heavily on informational ICMP.",
            severity="high",
            category="observation",
            citations=["sALERT_DOC_7Zk"],
        ),
    ]
    tool_results = [
        _labeled("t_query_events_oql", {"hits": [{"_id": "sALERT_DOC_7Zk"}]}),
    ]

    validated, counts = _validate_hunt_findings(findings, tool_results)

    assert validated[0].severity == "medium"  # medium threat untouched
    assert validated[0].validator_note is None
    assert validated[1].severity == "high"  # high OBSERVATION untouched
    assert validated[1].validator_note is None
    assert counts["findings_capped"] == 0


def test_validate_hunt_findings_get_event_raw_refetching_alert_is_not_corroboration() -> None:
    """F19: t_get_event_raw refetching the raw form of the SAME detector alert
    (event.dataset=suricata.alert) is the alert re-stated, not corroboration — a
    high threat citing only that raw alert doc is still capped to medium. Before
    the fix, t_get_event_raw was not doc-partitioned, so the refetched alert
    counted as corroboration and the finding stayed high."""
    from soc_ai.agent.hunt_gates import _validate_hunt_findings

    raw_alert_source = {
        "event": {"dataset": "suricata.alert", "kind": "alert"},
        "rule": {"name": "ET MALWARE BPFDoor ICMP Heartbeat"},
        "log": {"id": {"uid": "sRAWALERTUID42Qx"}},
    }
    findings = [
        HuntFinding(
            title="BPFDoor backdoor on 192.0.2.15",
            detail="Refetched the raw form of the ICMP heartbeat alert.",
            severity="high",
            category="threat",
            hosts=["192.0.2.15"],
            citations=["sRAWALERTUID42Qx"],  # the alert doc's own uid, refetched
        )
    ]
    tool_results = [_labeled("t_get_event_raw", raw_alert_source)]

    validated, counts = _validate_hunt_findings(findings, tool_results)

    f = validated[0]
    assert f.severity == "medium"  # capped — a refetched alert doc is not corroboration
    assert "only detector alerts cited" in (f.validator_note or "").lower()
    assert counts["findings_capped"] == 1


def test_validate_hunt_findings_get_event_raw_telemetry_doc_corroborates() -> None:
    """F19 companion: t_get_event_raw fetching a NON-alert telemetry doc
    (event.dataset=zeek.conn) IS real corroboration — it looked past the alert
    title — so a high threat citing it stays high. Guards against over-broadly
    denylisting the tool (which would drop this legitimate corroboration)."""
    from soc_ai.agent.hunt_gates import _validate_hunt_findings

    raw_zeek_source = {
        "event": {"dataset": "zeek.conn", "kind": "event"},
        "network": {"community_id": "1:zeekconncorrob"},
        "log": {"id": {"uid": "sRAWZEEKUID88Zt"}},
    }
    findings = [
        HuntFinding(
            title="Confirmed exfil on 10.0.0.5",
            detail="Zeek conn shows a large outbound-dominant transfer.",
            severity="high",
            category="threat",
            hosts=["10.0.0.5"],
            citations=["sRAWZEEKUID88Zt"],
        )
    ]
    tool_results = [_labeled("t_get_event_raw", raw_zeek_source)]

    validated, counts = _validate_hunt_findings(findings, tool_results)

    f = validated[0]
    assert f.severity == "high"  # NOT capped — a fetched telemetry doc corroborates
    assert f.validator_note is None
    assert counts["findings_capped"] == 0


def test_validate_hunt_findings_rule_content_is_not_corroboration() -> None:
    """t_get_rule_content is an alert-query tool (the signature is the detector's
    OWN claim), so a high threat citing only the alert + the rule text is STILL
    capped — reading the rule you're accused-by is not independent corroboration."""
    from soc_ai.agent.hunt_gates import _validate_hunt_findings

    findings = [
        HuntFinding(
            title="BPFDoor implant confirmed",
            detail="Alert fired and the rule content mentions BPFDoor.",
            severity="critical",
            category="threat",
            citations=["sALERT_DOC_7Zk", "sRULE_TEXT_3Xp"],
        )
    ]
    tool_results = [
        _labeled("t_query_events_oql", {"hits": [{"_id": "sALERT_DOC_7Zk"}]}),
        _labeled("t_get_rule_content", {"sid": "sRULE_TEXT_3Xp", "content": "BPFDoor magic"}),
    ]

    validated, counts = _validate_hunt_findings(findings, tool_results)

    f = validated[0]
    assert f.severity == "medium"  # critical → medium: no non-alert corroboration
    assert "only detector alerts cited" in (f.validator_note or "").lower()
    assert counts["findings_capped"] == 1


def test_validate_hunt_findings_labeled_evidence_resolution_unaffected() -> None:
    """The hunt_runner labeled-evidence change ({tool_name, result}) must NOT
    break the existing distinctive-token citation resolver — a fabricated id is
    still stripped, a real id still resolves, exactly as with the bare-result
    shape."""
    from soc_ai.agent.hunt_gates import _validate_hunt_findings

    tool_results = [
        _labeled("t_get_pcap", {"total": 1, "hits": [{"_id": "sREAL_PULLED_ID_42"}]}),
    ]
    # fabricated → stripped + capped
    fabricated = [
        HuntFinding(
            title="x", detail="d", severity="high", category="threat", citations=["sBOGUS_ID_9x"]
        )
    ]
    v1, c1 = _validate_hunt_findings(fabricated, tool_results)
    assert v1[0].citations == []
    assert v1[0].severity == "low"
    assert c1["citations_stripped"] == 1
    # real id → resolves AND corroborates (t_get_pcap is non-alert) → stays high
    real = [
        HuntFinding(
            title="x",
            detail="d",
            severity="high",
            category="threat",
            citations=["sREAL_PULLED_ID_42"],
        )
    ]
    v2, c2 = _validate_hunt_findings(real, tool_results)
    assert v2[0].citations == ["sREAL_PULLED_ID_42"]
    assert v2[0].severity == "high"
    assert c2["findings_capped"] == 0


def test_run_hunt_gathers_labeled_evidence_and_caps_alert_only_threat(
    settings_kratos: Settings,
) -> None:
    """End-to-end: run_hunt collects labeled {tool_name, result} evidence, and a
    high threat citing ONLY the streamed alert-query result is capped to medium
    with the corroborate-first note in the emitted hunt_report."""
    from types import SimpleNamespace

    from pydantic_ai.messages import ModelResponse, ToolCallPart, ToolReturnPart

    alert_id = "sALERT_DOC_7Zk"
    report = HuntReport(
        findings=[
            HuntFinding(
                title="BPFDoor backdoor on 192.0.2.15",
                detail="ICMP heartbeat alert matched BPFDoor.",
                severity="high",
                category="threat",
                hosts=["192.0.2.15"],
                citations=[alert_id],
            )
        ],
        narrative="An ICMP heartbeat alert fired.",
        affected_hosts=["192.0.2.15"],
        confidence=0.7,
    )

    class _Run:
        def __init__(self) -> None:
            self._nodes = iter(
                [
                    SimpleNamespace(
                        model_response=ModelResponse(
                            parts=[
                                ToolCallPart(
                                    tool_name="t_query_events_oql", args={}, tool_call_id="c1"
                                )
                            ]
                        ),
                        request=None,
                    ),
                    SimpleNamespace(
                        model_response=None,
                        request=SimpleNamespace(
                            parts=[
                                ToolReturnPart(
                                    tool_name="t_query_events_oql",
                                    content={"total": 1, "hits": [{"_id": alert_id}]},
                                    tool_call_id="c1",
                                )
                            ]
                        ),
                    ),
                ]
            )
            self.result = SimpleNamespace(output=report)

        async def __aenter__(self) -> _Run:
            return self

        async def __aexit__(self, *a: Any) -> bool:
            return False

        def __aiter__(self) -> _Run:
            return self

        async def __anext__(self) -> Any:
            try:
                return next(self._nodes)
            except StopIteration:
                raise StopAsyncIteration from None

    class _Agent:
        def iter(self, *a: Any, **k: Any) -> _Run:
            return _Run()

    async def _go() -> list[Any]:
        events = []
        with (
            patch("soc_ai.api.hunt_runner.build_hunt_agent", return_value=_Agent()),
            patch(
                "soc_ai.api.hunt_runner.build_investigator_model",
                return_value=TestModel(call_tools=[]),
            ),
        ):
            async for ev in run_hunt(_ctx(settings_kratos), objective="hunt BPFDoor"):
                events.append(ev)
        return events

    events = asyncio.run(_go())
    report_ev = next(e for e in events if e.kind == "hunt_report")
    f = report_ev.payload["findings"][0]
    assert f["severity"] == "medium"  # capped: cited only the detector alert
    assert "only detector alerts cited" in (f["validator_note"] or "").lower()


# ── Layer 3: deterministic partial-report humility ───────────────────────────


def test_apply_partial_humility_clamps_confidence_and_threat_severity() -> None:
    """A budget/timeout-partial report with conf 0.75 + a high threat finding →
    confidence clamped to <= 0.5, the threat capped to medium with the partial
    note; a non-threat finding and the narrative are untouched."""
    from soc_ai.api.hunt_runner import _apply_partial_humility

    report = HuntReport(
        findings=[
            HuntFinding(
                title="BPFDoor backdoor on 192.0.2.15",
                detail="Loud alert title.",
                severity="high",
                category="threat",
                citations=["sALERT_DOC_7Zk"],
            ),
            HuntFinding(
                title="No SSH telemetry on this grid",
                detail="Coverage gap.",
                severity="high",
                category="visibility_gap",
            ),
        ],
        narrative="Partial hunt — budget hit.",
        confidence=0.75,
    )

    clamped = _apply_partial_humility(report)

    assert clamped.confidence == 0.5  # clamped down from 0.75
    threat = clamped.findings[0]
    assert threat.severity == "medium"  # high threat capped
    assert threat.validator_note is not None
    assert "budget/timeout-partial" in threat.validator_note.lower()
    # the visibility_gap finding keeps its severity (only threats are capped)
    assert clamped.findings[1].severity == "high"
    assert clamped.findings[1].validator_note is None


def test_apply_partial_humility_leaves_low_confidence_untouched() -> None:
    """A partial report already below 0.5 keeps its confidence (clamp is a
    ceiling, never a floor)."""
    from soc_ai.api.hunt_runner import _apply_partial_humility

    report = HuntReport(narrative="clean partial", findings=[], confidence=0.2)
    assert _apply_partial_humility(report).confidence == 0.2


def test_run_hunt_partial_path_applies_humility(settings_kratos: Settings) -> None:
    """A budget-exhausted hunt whose synthesizer returns an over-confident report
    (conf 0.78, a high threat) has the humility clamp applied on the partial path:
    the emitted hunt_report is <= 0.5 conf with the threat capped to medium. A
    NON-partial run (separately covered) is never clamped."""
    from types import SimpleNamespace

    from pydantic_ai.exceptions import UsageLimitExceeded
    from pydantic_ai.messages import ModelResponse, TextPart

    over_confident = HuntReport(
        findings=[
            HuntFinding(
                title="BPFDoor backdoor on 192.0.2.15",
                detail="Asserted from a loud alert title.",
                severity="high",
                category="threat",
                citations=[],
            )
        ],
        narrative="Partial — budget hit mid-hunt.",
        confidence=0.78,
    )

    class _BudgetRun:
        result = None

        def __init__(self) -> None:
            self._nodes = iter(
                [
                    SimpleNamespace(
                        model_response=ModelResponse(parts=[TextPart(content="ran one query")]),
                        request=None,
                    )
                ]
            )

        async def __aenter__(self) -> _BudgetRun:
            return self

        async def __aexit__(self, *a: Any) -> bool:
            return False

        def __aiter__(self) -> _BudgetRun:
            return self

        async def __anext__(self) -> Any:
            try:
                return next(self._nodes)
            except StopIteration:
                raise UsageLimitExceeded("tool_calls_limit exceeded") from None

    class _BudgetAgent:
        def iter(self, *a: Any, **k: Any) -> _BudgetRun:
            return _BudgetRun()

    async def _go() -> list[Any]:
        events = []
        with (
            patch("soc_ai.api.hunt_runner.build_hunt_agent", return_value=_BudgetAgent()),
            patch(
                "soc_ai.api.hunt_runner._synthesize_partial_hunt",
                AsyncMock(return_value=SimpleNamespace(output=over_confident)),
            ),
        ):
            async for ev in run_hunt(_ctx(settings_kratos), objective="hunt BPFDoor"):
                events.append(ev)
        return events

    events = asyncio.run(_go())
    report_ev = next(e for e in events if e.kind == "hunt_report")
    assert report_ev.payload["confidence"] <= 0.5  # humility clamp applied
    f = report_ev.payload["findings"][0]
    assert f["severity"] == "medium"  # high threat capped on the partial path
    assert "budget/timeout-partial" in (f["validator_note"] or "").lower()


def test_run_hunt_full_run_report_not_clamped(settings_kratos: Settings) -> None:
    """A NORMAL (non-partial) hunt that legitimately reports conf 0.7 + a
    corroborated high threat is NOT touched by the partial-humility clamp — the
    clamp is gated strictly to the budget/timeout synthesis path."""
    from types import SimpleNamespace

    from pydantic_ai.messages import ModelResponse, ToolCallPart, ToolReturnPart

    real_id = "sPCAP_EVIDENCE_9Qm"
    report = HuntReport(
        findings=[
            HuntFinding(
                title="Confirmed C2 beacon",
                detail="Measured 60s cadence in the pcap.",
                severity="high",
                category="threat",
                citations=[real_id],
            )
        ],
        narrative="A confirmed beacon.",
        confidence=0.7,
    )

    class _Run:
        def __init__(self) -> None:
            self._nodes = iter(
                [
                    SimpleNamespace(
                        model_response=ModelResponse(
                            parts=[ToolCallPart(tool_name="t_get_pcap", args={}, tool_call_id="c1")]
                        ),
                        request=None,
                    ),
                    SimpleNamespace(
                        model_response=None,
                        request=SimpleNamespace(
                            parts=[
                                ToolReturnPart(
                                    tool_name="t_get_pcap",
                                    content={"beacon": {"interval_s": 60}, "marker": real_id},
                                    tool_call_id="c1",
                                )
                            ]
                        ),
                    ),
                ]
            )
            self.result = SimpleNamespace(output=report)

        async def __aenter__(self) -> _Run:
            return self

        async def __aexit__(self, *a: Any) -> bool:
            return False

        def __aiter__(self) -> _Run:
            return self

        async def __anext__(self) -> Any:
            try:
                return next(self._nodes)
            except StopIteration:
                raise StopAsyncIteration from None

    class _Agent:
        def iter(self, *a: Any, **k: Any) -> _Run:
            return _Run()

    async def _go() -> list[Any]:
        events = []
        with (
            patch("soc_ai.api.hunt_runner.build_hunt_agent", return_value=_Agent()),
            patch(
                "soc_ai.api.hunt_runner.build_investigator_model",
                return_value=TestModel(call_tools=[]),
            ),
        ):
            async for ev in run_hunt(_ctx(settings_kratos), objective="hunt beacon"):
                events.append(ev)
        return events

    events = asyncio.run(_go())
    report_ev = next(e for e in events if e.kind == "hunt_report")
    assert report_ev.payload["confidence"] == 0.7  # full-run confidence untouched
    f = report_ev.payload["findings"][0]
    assert f["severity"] == "high"  # corroborated threat kept high, not clamped
    assert f["validator_note"] is None


def test_replay_reasoning_context_lifts_thinking_into_synth_input(
    settings_kratos: Settings,
) -> None:
    """The reasoning-trace replay finding: the exploration model's ThinkingParts
    (where an FP was debunked) are lifted out of the gathered transcript and
    prepended to the synthesizer's user message, since pydantic-ai does NOT feed a
    prior turn's thinking into replayed history."""
    from pydantic_ai.messages import ModelRequest, ModelResponse, TextPart, UserPromptPart

    try:
        from pydantic_ai.messages import ThinkingPart
    except ImportError:  # pragma: no cover - pydantic-ai always ships ThinkingPart
        pytest.skip("ThinkingPart unavailable")

    from soc_ai.api.hunt_runner import _replay_reasoning_context, _synthesize_partial_hunt

    debunk = "192.0.2.15 shows Apple service discovery, not C2 — this is a false positive."
    gathered: list[Any] = [
        ModelRequest(parts=[UserPromptPart(content="hunt BPFDoor")]),
        ModelResponse(parts=[ThinkingPart(content=debunk), TextPart(content="Writing up.")]),
    ]

    # unit: the block carries the debunk verbatim
    block = _replay_reasoning_context(gathered)
    assert debunk in block
    assert "do NOT ignore it" in block

    # integration: the synthesizer's user message begins with the reasoning block
    seen: list[Any] = []
    with patch(
        "soc_ai.api.hunt_runner.build_investigator_model",
        return_value=_capturing_synth_model("partial writeup", seen),
    ):
        asyncio.run(
            _synthesize_partial_hunt(
                _ctx(settings_kratos), objective="hunt BPFDoor", gathered=gathered
            )
        )
    # the FunctionModel saw the reasoning block in the replayed user prompt
    flat = [getattr(p, "content", "") for msg in seen[0] for p in msg.parts]
    assert any(debunk in str(c) for c in flat)


def test_replay_reasoning_context_empty_when_no_thinking() -> None:
    """No ThinkingParts in the transcript → an empty reasoning block (the caller
    then omits it), so a non-reasoning model's synthesis is unchanged."""
    from pydantic_ai.messages import ModelRequest, ModelResponse, TextPart, UserPromptPart
    from soc_ai.api.hunt_runner import _replay_reasoning_context

    gathered: list[Any] = [
        ModelRequest(parts=[UserPromptPart(content="hunt")]),
        ModelResponse(parts=[TextPart(content="no thinking here")]),
    ]
    assert _replay_reasoning_context(gathered) == ""


# ── Layer 1: hunt-prompt skepticism language ─────────────────────────────────


def test_hunt_prompts_carry_detector_claim_skepticism() -> None:
    """Both hunt prompts must teach: a rule name is a claim, corroborate beyond the
    alert, run the OS-consistency check, and treat a solicited ICMP echo reply
    matching a heartbeat sig as an uncorroborated FP (the ported triage lesson)."""
    from soc_ai.agent.hunt import HUNT_SYNTH_PROMPT, HUNT_SYSTEM_PROMPT

    for p in (HUNT_SYSTEM_PROMPT, HUNT_SYNTH_PROMPT):
        low = p.lower()
        # a rule name is the detector's CLAIM, not an observation
        assert "detector's claim" in low or "detector claim" in low
        # corroborate beyond the alert document
        assert "corroborat" in low
        # OS-consistency: Apple telemetry ⇒ macOS/iOS, not a Linux backdoor
        assert "apple" in low
        assert "linux backdoor" in low
        # the specific solicited ICMP echo-reply / BPFDoor FP lesson
        assert "echo reply" in low
        assert "bpfdoor" in low


def test_hunt_system_prompt_softens_title_upgrade_pressure() -> None:
    """The old 'decisive C2 … do not discount because low-sev' pressure that
    pushed title-upgrading is reframed so decisiveness requires CORROBORATION, not
    the title (the measured pattern, not the alert name)."""
    from soc_ai.agent.hunt import HUNT_SYSTEM_PROMPT

    p = HUNT_SYSTEM_PROMPT
    assert "decisive C2" in p  # phrase kept (existing snapshot assertion)
    assert "ONCE CORROBORATED" in p
    # the reframed guidance ties decisiveness to the measured pattern, not the title
    low = p.lower()
    assert "not from the alert title" in low or "not\nfrom the alert title" in low


# ── Bulk hunt actions: re-hunt (clean re-run) + bulk delete ──────────────────


class _RecordingManager:
    """A stand-in for HuntConsoleManager that records every ``start`` call and
    hands back a synthetic new hunt id, so the bulk-rehunt endpoint's
    orchestration (dedup / skip reasons / concurrency cap / NO prior seeding) is
    tested deterministically without a live model or the background drainer.

    ``fail_ids`` lets a test simulate a start that returns None (could_not_start).
    """

    def __init__(self, fail_objectives: set[str] | None = None) -> None:
        self.calls: list[dict[str, Any]] = []
        self._fail = fail_objectives or set()
        self._n = 0

    async def start(self, _state: Any, **kwargs: Any) -> str | None:
        self.calls.append(kwargs)
        if kwargs.get("objective") in self._fail:
            return None
        self._n += 1
        return f"new-hunt-{self._n}"


def _seed_hunt(client: TestClient, *, objective: str, status: str) -> str:
    """Insert a hunt with a given status; returns its id."""

    async def _go() -> str:
        maker = client.app.state.db_sessionmaker
        async with maker() as db:
            hunt = await hunt_svc.create(db, objective=objective, started_by="admin")
            if status != "running":
                await hunt_svc.finalize(db, hunt.id, status=status, narrative="n")
            return hunt.id

    return asyncio.run(_go())


def test_bulk_rehunt_starts_fresh_hunts_without_prior_seeding(client: TestClient) -> None:
    """POST /hunts/rehunt starts a CLEAN fresh hunt per eligible id — same
    objective, and CRUCIALLY no ``prior`` (a re-hunt must not seed the old
    narrative). The response maps old→new ids + objective."""
    h1 = _seed_hunt(client, objective="hunt for beaconing", status="error")
    h2 = _seed_hunt(client, objective="hunt for lateral movement", status="complete")

    mgr = _RecordingManager()
    with patch("soc_ai.api.webui.routes_hunts.hunt_console_manager.get_manager", return_value=mgr):
        resp = client.post("/api/v1/hunts/rehunt", json={"hunt_ids": [h1, h2]})
    assert resp.status_code == 200
    body = resp.json()

    # both started, each mapped old→new with its objective
    started = {s["old_id"]: s for s in body["started"]}
    assert set(started) == {h1, h2}
    assert started[h1]["objective"] == "hunt for beaconing"
    assert started[h2]["new_id"].startswith("new-hunt-")
    assert body["skipped"] == []

    # NO prior seeding: every start passed the objective but never a `prior`.
    assert len(mgr.calls) == 2
    for call in mgr.calls:
        assert "prior" not in call or call["prior"] is None
    assert {c["objective"] for c in mgr.calls} == {
        "hunt for beaconing",
        "hunt for lateral movement",
    }


def test_bulk_rehunt_skips_running_and_not_found(client: TestClient) -> None:
    """A running hunt is skipped ('running' — nothing to re-run yet); an unknown
    id is skipped ('not_found'). Neither reaches the manager."""
    running = _seed_hunt(client, objective="live hunt", status="running")
    done = _seed_hunt(client, objective="done hunt", status="complete")

    mgr = _RecordingManager()
    with patch("soc_ai.api.webui.routes_hunts.hunt_console_manager.get_manager", return_value=mgr):
        resp = client.post(
            "/api/v1/hunts/rehunt", json={"hunt_ids": [running, done, "does-not-exist"]}
        )
    assert resp.status_code == 200
    body = resp.json()

    assert [s["old_id"] for s in body["started"]] == [done]
    reasons = {s["id"]: s["reason"] for s in body["skipped"]}
    assert reasons == {running: "running", "does-not-exist": "not_found"}
    # only the eligible one was actually started
    assert [c["objective"] for c in mgr.calls] == ["done hunt"]


def test_bulk_rehunt_dedups_input(client: TestClient) -> None:
    """A duplicated id is re-hunted ONCE (input deduped, order-preserving)."""
    h1 = _seed_hunt(client, objective="hunt A", status="complete")

    mgr = _RecordingManager()
    with patch("soc_ai.api.webui.routes_hunts.hunt_console_manager.get_manager", return_value=mgr):
        resp = client.post("/api/v1/hunts/rehunt", json={"hunt_ids": [h1, h1, h1]})
    assert resp.status_code == 200
    body = resp.json()
    assert [s["old_id"] for s in body["started"]] == [h1]
    assert len(mgr.calls) == 1


def test_bulk_rehunt_respects_concurrency_cap(client: TestClient) -> None:
    """Eligible ids beyond _REHUNT_START_CAP are skipped 'queued' — the endpoint
    starts at most K hunts so it never fires N concurrent hunts at the one model
    route (the 7-concurrent-hunts garbage incident)."""
    from soc_ai.api.webui.routes_hunts import _REHUNT_START_CAP

    n = _REHUNT_START_CAP + 2
    ids = [_seed_hunt(client, objective=f"hunt {i}", status="complete") for i in range(n)]

    mgr = _RecordingManager()
    with patch("soc_ai.api.webui.routes_hunts.hunt_console_manager.get_manager", return_value=mgr):
        resp = client.post("/api/v1/hunts/rehunt", json={"hunt_ids": ids})
    assert resp.status_code == 200
    body = resp.json()

    # exactly K started; the rest 'queued'
    assert len(body["started"]) == _REHUNT_START_CAP
    assert len(mgr.calls) == _REHUNT_START_CAP
    queued = [s for s in body["skipped"] if s["reason"] == "queued"]
    assert len(queued) == n - _REHUNT_START_CAP
    # the started ones are the FIRST K in input order (deferral, not drop)
    assert [s["old_id"] for s in body["started"]] == ids[:_REHUNT_START_CAP]


def test_bulk_rehunt_reports_could_not_start(client: TestClient) -> None:
    """A start that returns None (manager couldn't launch) is skipped
    'could_not_start' — surfaced, not silently dropped."""
    h1 = _seed_hunt(client, objective="doomed", status="error")

    mgr = _RecordingManager(fail_objectives={"doomed"})
    with patch("soc_ai.api.webui.routes_hunts.hunt_console_manager.get_manager", return_value=mgr):
        resp = client.post("/api/v1/hunts/rehunt", json={"hunt_ids": [h1]})
    assert resp.status_code == 200
    body = resp.json()
    assert body["started"] == []
    assert body["skipped"] == [{"id": h1, "reason": "could_not_start"}]


def test_bulk_rehunt_input_cap_is_422(client: TestClient) -> None:
    """An oversized hunt_ids list is rejected by request validation before the
    handler runs (mirrors the investigations rehunt input cap)."""
    from soc_ai.api.webui.routes_hunts import _REHUNT_CAP

    too_many = [f"id-{i}" for i in range(_REHUNT_CAP + 1)]
    resp = client.post("/api/v1/hunts/rehunt", json={"hunt_ids": too_many})
    assert resp.status_code == 422


def test_bulk_delete_removes_rows_and_reports_not_found(client: TestClient) -> None:
    """POST /hunts/bulk-delete removes each existing terminal hunt and reports an
    unknown id in not_found; the rows are gone from the list afterwards."""
    h1 = _seed_complete_hunt(client)
    h2 = _seed_hunt(client, objective="second hunt", status="complete")

    resp = client.post("/api/v1/hunts/bulk-delete", json={"hunt_ids": [h1, h2, "ghost", h1]})
    assert resp.status_code == 200
    body = resp.json()
    assert set(body["deleted"]) == {h1, h2}
    assert body["not_found"] == ["ghost"]

    remaining = {r["id"] for r in client.get("/api/v1/hunts").json()}
    assert h1 not in remaining and h2 not in remaining
    assert client.get(f"/api/v1/hunts/{h1}").status_code == 404


def test_bulk_delete_leaves_running_hunt(client: TestClient) -> None:
    """A still-running hunt is NOT deleted (its drainer could write back) — it's
    reported in not_found and remains listed."""
    running = _seed_hunt(client, objective="live hunt", status="running")
    done = _seed_hunt(client, objective="done hunt", status="complete")

    resp = client.post("/api/v1/hunts/bulk-delete", json={"hunt_ids": [running, done]})
    assert resp.status_code == 200
    body = resp.json()
    assert body["deleted"] == [done]
    assert body["not_found"] == [running]
    # the running hunt is still there
    assert client.get(f"/api/v1/hunts/{running}").status_code == 200


def _oql_hit(doc_id: str, dataset: str | None, kind: str | None = None) -> dict[str, Any]:
    """A minimal ES hit doc in the EsSearchResult.model_dump() shape the
    t_query_events_oql tool emits ({hits: [{_id, _source: {...}}]})."""
    src: dict[str, Any] = {}
    event: dict[str, Any] = {}
    if dataset is not None:
        event["dataset"] = dataset
    if kind is not None:
        event["kind"] = kind
    if event:
        src["event"] = event
    return {"_id": doc_id, "_index": "logs-x", "_source": src}


def test_oql_telemetry_docs_partitions_by_dataset() -> None:
    """Only docs POSITIVELY identified as non-alert telemetry survive the
    partition: zeek docs yes; suricata.alert docs no; docs with no
    event.dataset no; fields-form docs (list values) yes; non-dict results
    never raise."""
    from soc_ai.agent.hunt_gates import _oql_telemetry_docs

    result = {
        "total": 4,
        "hits": [
            _oql_hit("zeekDOC00", "zeek.conn"),
            _oql_hit("alrtDOC00", "suricata.alert", kind="alert"),
            _oql_hit("bareDOC00", None),  # no dataset — cannot be identified
            {  # fields-form doc (ES fields option returns list values)
                "_id": "fldsDOC00",
                "fields": {"event.dataset": ["zeek.dns"], "event.kind": ["event"]},
            },
        ],
    }
    kept = _oql_telemetry_docs(result)
    kept_ids = [d.get("_id") for d in kept]
    assert kept_ids == ["zeekDOC00", "fldsDOC00"]
    # Defensive shapes: never raise, never corroborate.
    assert _oql_telemetry_docs(None) == []
    assert _oql_telemetry_docs("boom") == []
    assert _oql_telemetry_docs({"aggregations": {"a": 1}}) == []


def test_validate_hunt_findings_oql_zeek_doc_now_corroborates() -> None:
    """THE fix the 2026-07-20 telemetry-latitude design exists for: a high
    THREAT finding whose citation resolves into a ZEEK doc fetched via
    t_query_events_oql keeps its severity. Before the doc-level partition,
    OQL was blanket non-corroborating and this capped to medium."""
    from soc_ai.agent.hunt_gates import _validate_hunt_findings

    findings = [
        HuntFinding(
            title="Beacon from 10.0.0.5 to 203.0.113.7",
            detail="Regular 60s cadence, low jitter, measured over 4h of conn records.",
            severity="high",
            category="threat",
            hosts=["10.0.0.5"],
            citations=["zeekCONN77abc"],
        )
    ]
    tool_results = [
        _labeled(
            "t_query_events_oql",
            {
                "total": 2,
                "hits": [
                    _oql_hit("zeekCONN77abc", "zeek.conn"),
                    _oql_hit("alrtNOISE99x", "suricata.alert", kind="alert"),
                ],
            },
        )
    ]
    validated, _stats = _validate_hunt_findings(findings, tool_results)
    assert validated[0].severity == "high"  # NOT capped — zeek doc corroborates


def test_validate_hunt_findings_oql_alert_doc_still_capped() -> None:
    """The trust floor holds: the SAME shape, but the citation resolves only
    into the suricata.alert doc inside the OQL result → still capped to
    medium with the corroborate-first note."""
    from soc_ai.agent.hunt_gates import _ALERT_ONLY_NOTE, _validate_hunt_findings

    findings = [
        HuntFinding(
            title="BPFDoor on 192.0.2.15",
            detail="The alert fired.",
            severity="high",
            category="threat",
            hosts=["192.0.2.15"],
            citations=["alrtDOC55zzz"],
        )
    ]
    tool_results = [
        _labeled(
            "t_query_events_oql",
            {
                "total": 2,
                "hits": [
                    _oql_hit("alrtDOC55zzz", "suricata.alert", kind="alert"),
                    _oql_hit("zeekOTHER11m", "zeek.conn"),  # present but NOT cited
                ],
            },
        )
    ]
    validated, _stats = _validate_hunt_findings(findings, tool_results)
    assert validated[0].severity == "medium"
    assert _ALERT_ONLY_NOTE in (validated[0].validator_note or "")
