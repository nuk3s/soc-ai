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
