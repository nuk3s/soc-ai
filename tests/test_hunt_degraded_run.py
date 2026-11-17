"""A slow or weak model run does not lose a hunt, and a weak run carries a mark.

Prod, 2026-10-31, hunt 01M69M3FVK9D6KECGCAXJK9F6Z: 42 tool calls, the wall
clock, then 25 minutes in the report writer and no report. The writer replays
the transcript as message history. The model answered it with two tool calls,
the writer runs with a tool-call limit of 0, and the page read
"UsageLimitExceeded ... tool_calls_limit of 0 (tool_calls=2)".

Prod, 2026-11-03, hunt 01M6HB9Y7JDA71ZEYME4N2MSF2: 36 model responses with no
reasoning trace, 3 false threat findings, and ``degraded: false``.

Three rules. The writer runs once more on a text copy of the evidence. A hunt
with no reasoning trace, on a deployment whose earlier hunts carried one,
takes a degraded mark that its findings state. A lost hunt states a plain
cause, and the raw error is a separate field.
"""

from __future__ import annotations

import asyncio
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient
from pydantic_ai.exceptions import UsageLimitExceeded
from pydantic_ai.messages import (
    ModelRequest,
    ModelResponse,
    TextPart,
    ThinkingPart,
    ToolCallPart,
    ToolReturnPart,
    UserPromptPart,
)
from pydantic_ai.models.function import AgentInfo, FunctionModel
from soc_ai.agent.hunt import HuntFinding, HuntReport
from soc_ai.agent.orchestrator import InvestigationContext
from soc_ai.api import hunt_runner
from soc_ai.api.hunt_recorder import error_narrative
from soc_ai.api.hunt_runner import (
    _NO_REASONING_NOTE,
    _reasoning_counts,
    _synthesize_partial_hunt,
    _text_transcript,
    hunt_recorded_run,
    run_hunt,
)
from soc_ai.config import Settings
from soc_ai.hunting import outcome as hunt_outcome
from soc_ai.main import create_app
from soc_ai.store import hunts as hunt_svc
from soc_ai.store.db import make_engine, make_sessionmaker, run_migrations
from soc_ai.store.models import Hunt

_OBJECTIVE = "Hunt for malicious activity over the past 72 hours."
_DOC = "docAAAAAAAAAAAAAAAA1"
_PROD_ERROR = "The next tool call(s) would exceed the tool_calls_limit of 0 (tool_calls=2)."
_PROD_NARRATIVE = (
    "The hunt failed: UsageLimitExceeded. hunt hit its budget and partial synthesis "
    f"failed: {_PROD_ERROR}"
)


def _ctx(settings: Settings, maker: Any = None) -> InvestigationContext:
    return InvestigationContext(
        settings=settings, auth=AsyncMock(), elastic=AsyncMock(), db_sessionmaker=maker
    )


def _gathered(*, thinking: bool = False) -> list[Any]:
    """The transcript of a hunt that ran one grid read and then its budget."""
    head: list[Any] = [ThinkingPart(content="The alert stream first.")] if thinking else []
    return [
        ModelRequest(parts=[UserPromptPart(content=_OBJECTIVE)]),
        ModelResponse(
            parts=[
                *head,
                TextPart(content="Reading the alert stream."),
                ToolCallPart(
                    tool_name="t_query_events_oql",
                    args={"query": "event.kind:alert"},
                    tool_call_id="c0",
                ),
            ]
        ),
        ModelRequest(
            parts=[
                ToolReturnPart(
                    tool_name="t_query_events_oql",
                    content={
                        "total": 1,
                        "hits": [{"_id": _DOC, "_source": {"rule": {"name": "R"}}}],
                    },
                    tool_call_id="c0",
                )
            ]
        ),
        ModelResponse(
            parts=[
                ToolCallPart(tool_name="t_query_events_oql", args={"q": "b"}, tool_call_id="c1"),
                ToolCallPart(tool_name="t_query_events_oql", args={"q": "c"}, tool_call_id="c2"),
            ]
        ),
    ]


class _Run:
    """An agent run that streams ``gathered`` and then ends as told."""

    def __init__(self, gathered: list[Any], end: BaseException | None, result: Any) -> None:
        self._nodes = iter(
            SimpleNamespace(
                model_response=m if isinstance(m, ModelResponse) else None,
                request=m if isinstance(m, ModelRequest) else None,
            )
            for m in gathered
        )
        self._end = end
        self.result = result

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
            if self._end is not None:
                raise self._end from None
            raise StopAsyncIteration from None


class _Agent:
    def __init__(
        self, gathered: list[Any], *, end: BaseException | None = None, result: Any = None
    ) -> None:
        self._args = (gathered, end, result)

    def iter(self, *a: Any, **k: Any) -> _Run:
        return _Run(*self._args)


def _budget_agent(gathered: list[Any] | None = None) -> _Agent:
    return _Agent(gathered or _gathered(), end=UsageLimitExceeded("tool_calls_limit exceeded"))


def _has_tool_parts(messages: list[Any]) -> bool:
    return any(
        isinstance(p, (ToolCallPart, ToolReturnPart))
        for m in messages
        for p in getattr(m, "parts", [])
    )


def _weak_synth_model(seen: list[list[Any]], *, always_calls_a_tool: bool = False) -> FunctionModel:
    """A report writer that answers a history of tool calls with one more tool call.

    That is the model of the prod hunt. Shown text only, it writes the report.
    """

    def _fn(messages: list[Any], info: AgentInfo) -> ModelResponse:
        seen.append(list(messages))
        if always_calls_a_tool or _has_tool_parts(messages):
            return ModelResponse(
                parts=[
                    ToolCallPart(tool_name="t_query_events_oql", args={"query": "one more"}),
                    ToolCallPart(tool_name="t_query_events_oql", args={"query": "and one"}),
                ]
            )
        return ModelResponse(
            parts=[
                ToolCallPart(
                    tool_name=info.output_tools[0].name,
                    args={
                        "narrative": "Suspicious: one host exploits the app.",
                        "confidence": 0.9,
                        "findings": [
                            {
                                "title": "Host exploits the app",
                                "detail": "One alert names the exploit.",
                                "severity": "high",
                                "category": "threat",
                                "hosts": ["192.0.2.164"],
                                "citations": [_DOC],
                            }
                        ],
                    },
                )
            ]
        )

    return FunctionModel(_fn)


async def _events(ctx: InvestigationContext, agent: Any, model: Any) -> list[Any]:
    out = []
    with (
        patch("soc_ai.api.hunt_runner.build_hunt_agent", return_value=agent),
        patch("soc_ai.api.hunt_runner.build_investigator_model", return_value=model),
    ):
        async for ev in run_hunt(ctx, objective=_OBJECTIVE):
            out.append(ev)
    return out


# ── the report writer runs again on a text transcript ───────────────────────


def test_the_replayed_transcript_stops_the_writer_on_a_tool_call(settings_kratos: Settings) -> None:
    """The root cause, on the real library: a tool call under a limit of 0 ends the run."""
    seen: list[list[Any]] = []
    with (
        patch(
            "soc_ai.api.hunt_runner.build_investigator_model", return_value=_weak_synth_model(seen)
        ),
        pytest.raises(UsageLimitExceeded, match="tool_calls_limit of 0"),
    ):
        asyncio.run(
            _synthesize_partial_hunt(
                _ctx(settings_kratos), objective=_OBJECTIVE, gathered=_gathered()
            )
        )
    assert len(seen) == 1 and _has_tool_parts(seen[0])


def test_the_text_transcript_holds_the_evidence_and_no_tool_part() -> None:
    text = _text_transcript(_gathered(thinking=True))

    assert 'Tool call t_query_events_oql: {"query": "event.kind:alert"}' in text
    assert f'"_id": "{_DOC}"' in text
    assert "Model note: Reading the alert stream." in text
    # The reasoning travels in its own block, and the objective in the instructions.
    assert "The alert stream first." not in text
    assert _OBJECTIVE not in text
    assert _text_transcript([]) == ""


def test_a_hunt_that_lost_its_report_lands_it_from_the_text_copy(settings_kratos: Settings) -> None:
    seen: list[list[Any]] = []

    events = asyncio.run(_events(_ctx(settings_kratos), _budget_agent(), _weak_synth_model(seen)))

    kinds = [e.kind for e in events]
    assert "error" not in kinds
    assert kinds[-1] == "done"
    report = next(e for e in events if e.kind == "hunt_report").payload
    assert report["narrative"] == "Suspicious: one host exploits the app."
    assert any(e.payload.get("text") == hunt_runner._TEXT_RETRY_NOTE for e in events)
    # Two attempts. The second one read text only, and the text held the evidence.
    assert len(seen) == 2
    assert _has_tool_parts(seen[0]) and not _has_tool_parts(seen[1])
    prompt = "\n".join(
        str(p.content) for m in seen[1] for p in m.parts if isinstance(p, UserPromptPart)
    )
    assert _DOC in prompt
    assert "Write the HuntReport now" in prompt
    # The report is still a partial report: the humility clamp and the mark hold.
    done = events[-1].payload
    assert done["partial"] is True
    assert report["confidence"] <= 0.5
    assert report["findings"][0]["severity"] == "medium"
    assert "partial report" in report["findings"][0]["validator_note"]


def test_a_writer_that_calls_a_tool_on_text_too_still_loses_the_hunt(
    settings_kratos: Settings,
) -> None:
    """Negative control: the second attempt is the last one, and the loss is stated."""
    seen: list[list[Any]] = []
    model = _weak_synth_model(seen, always_calls_a_tool=True)

    events = asyncio.run(_events(_ctx(settings_kratos), _budget_agent(), model))

    kinds = [e.kind for e in events]
    assert kinds[-1] == "error" and "hunt_report" not in kinds
    payload = events[-1].payload
    assert payload["stage"] == "partial_synthesis" and payload["limit"] == "budget"
    assert payload["message"].startswith("hunt hit its budget and partial synthesis failed:")
    # The request limit of the second attempt bounds it.
    assert 2 <= len(seen) <= 4


def test_a_failure_that_is_no_usage_limit_gets_no_second_attempt(settings_kratos: Settings) -> None:
    """Negative control: a gateway error on the writer is not a transcript problem."""
    calls = 0

    async def _fail(*a: Any, **k: Any) -> Any:
        nonlocal calls
        calls += 1
        raise RuntimeError("status_code: 500, model_name: m, body: Cannot connect to host")

    async def _go() -> list[Any]:
        out = []
        with (
            patch("soc_ai.api.hunt_runner.build_hunt_agent", return_value=_budget_agent()),
            patch("soc_ai.api.hunt_runner.build_investigator_model", return_value=object()),
            patch("soc_ai.api.hunt_runner._synthesize_partial_hunt", _fail),
        ):
            async for ev in run_hunt(_ctx(settings_kratos), objective=_OBJECTIVE):
                out.append(ev)
        return out

    events = asyncio.run(_go())

    assert calls == 1
    assert events[-1].kind == "error"
    assert not any(e.payload.get("text") == hunt_runner._TEXT_RETRY_NOTE for e in events)


def test_a_timed_out_hunt_names_the_time_limit(settings_kratos: Settings) -> None:
    async def _fail(*a: Any, **k: Any) -> Any:
        raise UsageLimitExceeded(_PROD_ERROR)

    async def _go() -> list[Any]:
        out = []
        agent = _Agent(_gathered(), end=TimeoutError())
        with (
            patch("soc_ai.api.hunt_runner.build_hunt_agent", return_value=agent),
            patch("soc_ai.api.hunt_runner.build_investigator_model", return_value=object()),
            patch("soc_ai.api.hunt_runner._synthesize_partial_hunt", _fail),
        ):
            async for ev in run_hunt(_ctx(settings_kratos), objective=_OBJECTIVE):
                out.append(ev)
        return out

    payload = asyncio.run(_go())[-1].payload

    assert payload["limit"] == "time"
    cause = error_narrative(payload["message"], payload["type"])
    assert cause.startswith("The hunt reached its time limit before it wrote a report.")
    assert "tool_calls_limit" not in cause


# ── the plain cause of a lost hunt ──────────────────────────────────────────


def test_the_prod_error_reads_as_a_plain_cause() -> None:
    cause = hunt_outcome.failure_cause(
        f"hunt hit its budget and partial synthesis failed: {_PROD_ERROR}", "UsageLimitExceeded"
    )

    assert cause == (
        "The hunt reached its budget before it wrote a report. The model then answered "
        "with a tool call and wrote no report. The trace shows what the hunt read. Hunt again."
    )
    # An older row holds the raw sentence. The page maps it on read.
    assert hunt_outcome.restate_hunt_failure(_PROD_NARRATIVE) == cause
    assert hunt_outcome.stored_failure_detail(_PROD_NARRATIVE) == (
        f"UsageLimitExceeded: hunt hit its budget and partial synthesis failed: {_PROD_ERROR}"
    )


@pytest.mark.parametrize(
    ("exc_type", "message", "expected"),
    [
        (
            "ModelHTTPError",
            "status_code: 500, model_name: m, body: {'message': 'Cannot connect to host x:8888'}",
            "The model backend did not accept a connection. "
            "Check the model gateway in Settings. Then hunt again.",
        ),
        (
            "ModelHTTPError",
            "status_code: 502, model_name: m, body:",
            "The model gateway returned an error with status 502. "
            "Check the model gateway in Settings. Then hunt again.",
        ),
        (
            "ModelHTTPError",
            "hunt hit its budget and partial synthesis failed: status_code: 500, "
            "model_name: m, body: {'message': 'Cannot connect to host x:8888'}",
            "The hunt reached its budget before it wrote a report. The model backend did "
            "not accept a connection. The hunt has no report. "
            "Check the model gateway in Settings. Then hunt again.",
        ),
        (
            "EmptyResult",
            "hunt produced no report",
            "The model ended the hunt and wrote no report. Hunt again.",
        ),
        (
            "ConnectionTimeout",
            "precondition: ConnectionTimeout caused by ReadTimeout",
            "The data source did not answer in time during the precondition query.",
        ),
        ("RuntimeError", "something this build does not know", hunt_outcome.UNKNOWN_FAILURE),
    ],
)
def test_each_class_of_lost_hunt_has_a_plain_cause(
    exc_type: str, message: str, expected: str
) -> None:
    cause = hunt_outcome.failure_cause(message, exc_type)

    assert cause == expected
    # The raw text of the error is never in the plain cause.
    assert "status_code" not in cause and exc_type not in cause


def test_a_grid_error_is_not_blamed_on_the_model() -> None:
    """Negative control: the grid client words a refused connection the same way."""
    cause = hunt_outcome.failure_cause(
        "ConnectionError(Cannot connect to host 192.0.2.253:9200 ssl:default)", "ConnectionError"
    )

    assert cause == "The data source did not accept a connection."


@pytest.mark.parametrize(
    "narrative",
    [
        "The hunt failed: the model gateway refused the connection.",
        "The hunt failed.",
        "The data source did not answer in time.",
        "**Grid unavailable. The hunt could not read the network.** All 2 grid queries failed.",
    ],
)
def test_a_sentence_of_another_shape_is_not_rewritten(narrative: str) -> None:
    """Negative control: only the recorder's own old shape is mapped on read."""
    assert hunt_outcome.restate_hunt_failure(narrative) == narrative
    assert hunt_outcome.stored_failure_detail(narrative) is None


async def _store(settings: Settings) -> tuple[Any, Any]:
    engine = make_engine(settings)
    await run_migrations(engine)
    return engine, make_sessionmaker(engine)


def test_a_crashed_hunt_stores_the_plain_cause_and_keeps_the_raw_error(
    settings_kratos: Settings,
) -> None:
    async def _go() -> tuple[str, list[Any]]:
        engine, maker = await _store(settings_kratos)
        state = SimpleNamespace(db_sessionmaker=maker)
        hunt_id = ""
        with patch(
            "soc_ai.api.hunt_runner.build_investigator_model",
            side_effect=RuntimeError("the model gateway refused the connection"),
        ):
            async for name, data in hunt_recorded_run(
                state, ctx=_ctx(settings_kratos), objective=_OBJECTIVE, started_by="admin"
            ):
                if name == "hunt_created":
                    hunt_id = data["hunt_id"]
        async with maker() as db:
            got = await hunt_svc.get_with_events(db, hunt_id)
        await engine.dispose()
        assert got is not None
        return got[0].narrative or "", [e for e in got[1] if e.kind == "error"]

    narrative, errors = asyncio.run(_go())

    assert narrative == hunt_outcome.UNKNOWN_FAILURE
    assert len(errors) == 1
    assert errors[0].payload["type"] == "RuntimeError"
    assert errors[0].payload["message"] == "the model gateway refused the connection"


# ── the degraded mark ───────────────────────────────────────────────────────


def _report(**over: Any) -> HuntReport:
    return HuntReport(
        narrative="Suspicious: one host beacons.",
        confidence=0.7,
        findings=[
            HuntFinding(
                title="Host beacons to a listed address",
                detail="The flows are periodic.",
                severity="medium",
                hosts=["192.0.2.10"],
                citations=[_DOC],
                validator_note=over.get("note"),
            )
        ],
    )


async def _seed_earlier_hunt(maker: Any, *, reasoning: bool) -> None:
    async with maker() as db:
        hunt = await hunt_svc.create(db, objective="an earlier hunt", started_by="scheduler")
        payload: dict[str, Any] = {"content": "Reading."}
        if reasoning:
            payload["reasoning_trace"] = "The alert stream first."
        await hunt_svc.append_events(
            db, hunt.id, [{"sequence": 1, "kind": "model_response", "payload": payload}]
        )
        await hunt_svc.finalize(db, hunt.id, status="complete", report={"findings": []})


def _complete_agent(*, thinking: bool) -> _Agent:
    """A hunt that ends with a report. The first three messages are its grid read."""
    return _Agent(_gathered(thinking=thinking)[:3], result=SimpleNamespace(output=_report()))


async def _hunt_events(settings: Settings, *, earlier: bool | None, thinking: bool) -> list[Any]:
    engine, maker = await _store(settings)
    if earlier is not None:
        await _seed_earlier_hunt(maker, reasoning=earlier)
    try:
        return await _events(_ctx(settings, maker), _complete_agent(thinking=thinking), object())
    finally:
        await engine.dispose()


def test_the_reasoning_counts_read_both_trace_shapes() -> None:
    inline = [ModelResponse(parts=[TextPart(content="<think>why</think>The answer.")])]

    assert _reasoning_counts(_gathered()) == (2, 0)
    assert _reasoning_counts(_gathered(thinking=True)) == (2, 1)
    assert _reasoning_counts(inline) == (1, 1)
    assert _reasoning_counts([]) == (0, 0)


def test_a_hunt_with_no_reasoning_trace_takes_the_mark(settings_kratos: Settings) -> None:
    events = asyncio.run(_hunt_events(settings_kratos, earlier=True, thinking=False))

    report = next(e for e in events if e.kind == "hunt_report").payload
    assert report["degraded"] == {"reason": "no_reasoning_trace", "model_responses": 1}
    assert hunt_outcome.degraded_reason(report) == "no_reasoning_trace"
    assert report["findings"][0]["validator_note"] == _NO_REASONING_NOTE
    done = events[-1].payload
    assert done["no_reasoning_trace"] is True
    assert (done["model_responses"], done["reasoning_traces"]) == (1, 0)
    # The hunt read the grid. It is not the blind run that ends in an error.
    assert done["degraded"] is False
    # The model text and the grades stay as the model wrote them.
    assert report["narrative"] == "Suspicious: one host beacons."
    assert report["confidence"] == 0.7
    assert report["findings"][0]["severity"] == "medium"


def test_a_hunt_with_a_reasoning_trace_takes_no_mark(settings_kratos: Settings) -> None:
    """Negative control: the normal run."""
    events = asyncio.run(_hunt_events(settings_kratos, earlier=True, thinking=True))

    report = next(e for e in events if e.kind == "hunt_report").payload
    assert "degraded" not in report
    assert report["findings"][0]["validator_note"] is None
    assert events[-1].payload["no_reasoning_trace"] is False


@pytest.mark.parametrize("earlier", [False, None])
def test_a_deployment_whose_model_never_reasons_takes_no_mark(
    settings_kratos: Settings, earlier: bool | None
) -> None:
    """Negative control: with no trace on any earlier hunt, a mark says nothing."""
    events = asyncio.run(_hunt_events(settings_kratos, earlier=earlier, thinking=False))

    report = next(e for e in events if e.kind == "hunt_report").payload
    assert "degraded" not in report
    assert report["findings"][0]["validator_note"] is None
    assert events[-1].payload["no_reasoning_trace"] is False


def test_the_mark_joins_a_note_that_a_gate_wrote() -> None:
    marked = hunt_runner._mark_no_reasoning(
        _report(note="The citations name no gathered evidence.")
    )

    assert marked.findings[0].validator_note == (
        f"The citations name no gathered evidence. {_NO_REASONING_NOTE}"
    )


def test_a_marked_run_is_no_earlier_conclusion(settings_kratos: Settings) -> None:
    """The next scheduled hunt does not read the findings of a degraded run."""

    async def _go() -> list[str]:
        engine, maker = await _store(settings_kratos)
        now = datetime.now(UTC).replace(tzinfo=None)
        ids: list[str] = []
        async with maker() as db:
            for hours, degraded in ((30, False), (6, True)):
                hunt = await hunt_svc.create(
                    db, objective=_OBJECTIVE, started_by="scheduler", kind="scheduled"
                )
                row = await db.get(Hunt, hunt.id)
                assert row is not None
                row.created_at = now - timedelta(hours=hours)
                await db.commit()
                report: dict[str, Any] = {"findings": [], "narrative": "n"}
                if degraded:
                    report["degraded"] = {"reason": "no_reasoning_trace"}
                await hunt_svc.finalize(db, hunt.id, status="complete", report=report)
                ids.append(hunt.id)
            runs = await hunt_svc.earlier_runs(db, objective=_OBJECTIVE, before=now)
        await engine.dispose()
        assert [r.id for r in runs] == [ids[0]]
        return ids

    asyncio.run(_go())


# ── the page ────────────────────────────────────────────────────────────────


@pytest.fixture
def client(settings_kratos: Settings) -> Iterator[TestClient]:
    with (
        patch("soc_ai.so_client.elastic.AsyncElasticsearch", return_value=AsyncMock()),
        patch("soc_ai.main.make_auth", return_value=AsyncMock()),
        patch("soc_ai.main.get_settings", return_value=settings_kratos),
    ):
        app = create_app()
        with TestClient(app) as test_client:
            yield test_client


def _seed(client: TestClient, *, status: str, report: dict[str, Any] | None, **kw: Any) -> str:
    async def _go() -> str:
        maker = client.app.state.db_sessionmaker  # type: ignore[attr-defined]
        async with maker() as db:
            hunt = await hunt_svc.create(db, objective=_OBJECTIVE, started_by="scheduler")
            if kw.get("events"):
                await hunt_svc.append_events(db, hunt.id, kw["events"])
            await hunt_svc.finalize(
                db, hunt.id, status=status, narrative=kw.get("narrative"), report=report
            )
            return hunt.id

    return asyncio.run(_go())


def test_the_api_states_the_degraded_mark_on_the_row_and_the_page(client: TestClient) -> None:
    report = _report().model_dump(mode="json")
    marked = _seed(
        client,
        status="complete",
        report={**report, "degraded": {"reason": "no_reasoning_trace", "model_responses": 36}},
    )
    plain = _seed(client, status="complete", report=report)

    detail = client.get(f"/api/v1/hunts/{marked}").json()
    rows = {h["id"]: h for h in client.get("/api/v1/hunts").json()}

    assert detail["degraded"] == "no_reasoning_trace"
    assert detail["degradedNote"] == (
        "The model returned no reasoning trace in this hunt. Earlier hunts carried one. "
        "Check each finding against its evidence."
    )
    assert rows[marked]["degraded"] == "no_reasoning_trace"
    assert rows[marked]["degradedNote"] == detail["degradedNote"]
    # Negative control: a normal hunt carries no mark.
    assert client.get(f"/api/v1/hunts/{plain}").json()["degraded"] is None
    assert rows[plain]["degraded"] is None and rows[plain]["degradedNote"] is None


def test_the_page_of_a_lost_hunt_states_the_cause_and_holds_the_raw_error(
    client: TestClient,
) -> None:
    message = f"hunt hit its budget and partial synthesis failed: {_PROD_ERROR}"
    new = _seed(
        client,
        status="error",
        report=None,
        narrative=error_narrative(message, "UsageLimitExceeded"),
        events=[
            {
                "sequence": 9,
                "kind": "error",
                "payload": {"message": message, "type": "UsageLimitExceeded"},
            }
        ],
    )
    # The prod row: the raw sentence in the narrative, as the older build stored it.
    old = _seed(client, status="error", report=None, narrative=_PROD_NARRATIVE)

    for hunt_id in (new, old):
        detail = client.get(f"/api/v1/hunts/{hunt_id}").json()
        assert detail["outcome"] == "could_not_run"
        assert detail["outcome_headline"].startswith(
            "The hunt reached its budget before it wrote a report."
        )
        assert "tool_calls_limit" not in detail["outcome_headline"]
        assert "UsageLimitExceeded" not in detail["outcome_headline"]
        assert detail["errorDetail"] == f"UsageLimitExceeded: {message}"
    rows = {h["id"]: h for h in client.get("/api/v1/hunts").json()}
    assert "tool_calls_limit" not in rows[old]["outcome_headline"]


def test_a_hunt_that_did_not_fail_holds_no_error_detail(client: TestClient) -> None:
    done = _seed(client, status="complete", report=_report().model_dump(mode="json"))

    assert client.get(f"/api/v1/hunts/{done}").json()["errorDetail"] is None


# ── review fixes: the note, the cause of each class, the usage ──────────────


@pytest.mark.parametrize(
    "gate_note", ["_UNRESOLVED_NOTE", "_HIGH_NO_CITE_NOTE", "_ALERT_ONLY_NOTE"]
)
def test_a_reworded_gate_note_keeps_the_degraded_note(gate_note: str) -> None:
    """The page reworded the gate note and dropped the mark behind it."""
    from soc_ai.agent import hunt_gates
    from soc_ai.hunting.hunt_words import validator_note

    stored = f"{getattr(hunt_gates, gate_note)} {_NO_REASONING_NOTE}"

    shown = validator_note(stored)

    assert shown is not None and shown.endswith(_NO_REASONING_NOTE)
    # The gate note is still reworded: the page prints its words, once.
    assert shown != stored or gate_note == "_ALERT_ONLY_NOTE"
    assert shown.count(_NO_REASONING_NOTE) == 1
    # Negative controls: the mark alone, and a gate note alone.
    assert validator_note(_NO_REASONING_NOTE) == _NO_REASONING_NOTE
    alone = validator_note(getattr(hunt_gates, gate_note))
    assert alone is not None and "reasoning trace" not in alone


def test_the_page_states_the_mark_on_a_finding_with_a_gate_note(client: TestClient) -> None:
    from soc_ai.agent import hunt_gates

    report = _report(note=f"{hunt_gates._UNRESOLVED_NOTE} {_NO_REASONING_NOTE}").model_dump(
        mode="json"
    )
    hunt_id = _seed(
        client, status="complete", report={**report, "degraded": {"reason": "no_reasoning_trace"}}
    )

    note = client.get(f"/api/v1/hunts/{hunt_id}").json()["findings"][0]["validatorNote"]

    assert note.startswith("The citations name no gathered evidence.")
    assert note.endswith(_NO_REASONING_NOTE)


_BUDGET = "hunt hit its budget and partial synthesis failed: "
_HEAD = "The hunt reached its budget before it wrote a report. "


@pytest.mark.parametrize(
    ("exc_type", "message", "expected"),
    [
        # The redaction guard stopped the report writer. No model call ran.
        (
            "EgressResidueError",
            _BUDGET + "1 internal identifier(s) survived sanitization on an outbound payload",
            _HEAD + "The redaction then stopped the report writer. The text holds an internal "
            "name that the redaction cannot remove, so no text went to the model. "
            "Check the redaction settings. Then hunt again.",
        ),
        (
            "EgressResidueError",
            "1 internal identifier(s) survived sanitization on an outbound payload",
            "The redaction stopped the hunt before the model read the prompt. The text holds an "
            "internal name that the redaction cannot remove, so no text went to the model. "
            "Check the redaction settings. Then hunt again.",
        ),
        # The report writer used its three requests. No tool call ended it.
        (
            "UsageLimitExceeded",
            _BUDGET + "The next request would exceed the request_limit of 3",
            _HEAD + "The model then used every request of the report writer and wrote no "
            "report. The trace shows what the hunt read. Hunt again.",
        ),
        (
            "UsageLimitExceeded",
            _BUDGET + _PROD_ERROR,
            _HEAD + "The model then answered with a tool call and wrote no report. "
            "The trace shows what the hunt read. Hunt again.",
        ),
        # The body of a 400 quotes the words "rate limit". The status decides.
        (
            "ModelHTTPError",
            "status_code: 400, model_name: m, body: {'message': 'context length exceeded; "
            "the prompt mentions a rate limit and a quota'}",
            "The model gateway refused the request with status 400. "
            "Check the model gateway in Settings. Then hunt again.",
        ),
        (
            "ModelHTTPError",
            "status_code: 429, model_name: m, body: {}",
            "The model gateway refused the request. The rate limit or the quota is used up. "
            "Check the model gateway in Settings. Then hunt again.",
        ),
        # A timeout that names no service is blamed on no service.
        (
            "ReadTimeout",
            "timed out",
            "A request of the hunt did not answer in time. The error text does not name the "
            "service. Hunt again.",
        ),
    ],
)
def test_each_way_a_hunt_is_lost_has_its_own_true_sentence(
    exc_type: str, message: str, expected: str
) -> None:
    assert hunt_outcome.failure_cause(message, exc_type) == expected


def test_the_usage_of_a_failed_report_attempt_is_recorded(settings_kratos: Settings) -> None:
    """The first attempt of the prod hunt ran 25 minutes and left no record of its cost."""
    seen: list[list[Any]] = []

    events = asyncio.run(_events(_ctx(settings_kratos), _budget_agent(), _weak_synth_model(seen)))

    usage = [e.payload for e in events if e.kind == "usage"]
    failed = [u for u in usage if u["phase"] == "hunt_partial_synth_failed"]
    landed = [u for u in usage if u["phase"] == "hunt_partial_synth"]
    assert len(failed) == 1 and failed[0]["requests"] == 1
    assert len(landed) == 1 and landed[0]["requests"] == 1
    # The failed attempt comes first in the trace, before the note of the retry.
    kinds = [(e.kind, e.payload.get("phase") or e.payload.get("text")) for e in events]
    assert kinds.index(("usage", "hunt_partial_synth_failed")) < kinds.index(
        ("model_response", hunt_runner._TEXT_RETRY_NOTE)
    )


def test_a_lost_hunt_records_the_usage_of_both_attempts(settings_kratos: Settings) -> None:
    seen: list[list[Any]] = []
    model = _weak_synth_model(seen, always_calls_a_tool=True)

    events = asyncio.run(_events(_ctx(settings_kratos), _budget_agent(), model))

    failed = [
        e.payload
        for e in events
        if e.kind == "usage" and e.payload["phase"] == "hunt_partial_synth_failed"
    ]
    assert len(failed) == 2
    assert sum(u["requests"] for u in failed) == len(seen)
    assert events[-1].kind == "error"


def test_an_attempt_that_made_no_request_records_no_usage(settings_kratos: Settings) -> None:
    """Negative control: the redaction stops the writer before a model call."""

    async def _fail(*a: Any, **k: Any) -> Any:
        raise RuntimeError("stopped before the model")

    async def _go() -> list[Any]:
        out = []
        with (
            patch("soc_ai.api.hunt_runner.build_hunt_agent", return_value=_budget_agent()),
            patch("soc_ai.api.hunt_runner.build_investigator_model", return_value=object()),
            patch("soc_ai.api.hunt_runner._synthesize_partial_hunt", _fail),
        ):
            async for ev in run_hunt(_ctx(settings_kratos), objective=_OBJECTIVE):
                out.append(ev)
        return out

    events = asyncio.run(_go())

    assert not [
        e for e in events if e.kind == "usage" and "partial_synth" in str(e.payload.get("phase"))
    ]
