"""A run that hits the output token limit before a response runs once more (B6).

Production recorded 12 runs with "Model token limit (32000) exceeded before any
response was generated" from 2026-11-04 to 2026-11-12 (review 2026-11-12, ops
finding 8). All were on binary-payload rules. Each run lost 2 to 9 minutes of
model time and reached no verdict.

The fix runs the stopped model call one more time with low reasoning effort:

- A synthesis call runs again with the same prompt.
- The investigation loop resumes from the history before the stopped turn, so
  no tool runs twice.
- One retry only. A second stop lands the failure that it landed before.
- Any other model error gets no retry.
"""

from __future__ import annotations

import json
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest
from pydantic_ai import Agent
from pydantic_ai.exceptions import UnexpectedModelBehavior
from pydantic_ai.messages import (
    ModelRequest,
    ModelResponse,
    TextPart,
    ThinkingPart,
    ToolCallPart,
    ToolReturnPart,
    UserPromptPart,
)
from pydantic_ai.models.test import TestModel
from pydantic_ai.usage import RunUsage, UsageLimits
from soc_ai.agent import orchestrator as orch
from soc_ai.agent.models import (
    LOW_REASONING_EFFORT,
    build_synthesizer_model,
    is_token_limit_before_response,
    low_reasoning_settings,
)
from soc_ai.agent.orchestrator import investigate
from soc_ai.agent.triage import InvestigationTranscript, TriageReport
from soc_ai.audit.schemas import AuditEvent
from soc_ai.config import Settings
from soc_ai.webui.timeline_labels import label_event

from tests import test_hunt_subject as hs

TOKEN_LIMIT = (
    "Model token limit (32000) exceeded before any response was generated. "
    "Increase the `max_tokens` model setting, or simplify the prompt to result in a "
    "shorter response that will fit within the limit."
)


# The counters of the attempt that the token limit stopped.
STOPPED_USAGE = RunUsage(requests=2, tool_calls=1, input_tokens=900, output_tokens=32000)


def _token_limit() -> UnexpectedModelBehavior:
    return UnexpectedModelBehavior(TOKEN_LIMIT)


# ── the error class ───────────────────────────────────────────────────────────


def test_the_token_limit_error_is_recognized() -> None:
    assert is_token_limit_before_response(_token_limit())
    assert is_token_limit_before_response(
        UnexpectedModelBehavior(
            "Model token limit (provider default) exceeded before any response was generated."
        )
    )


@pytest.mark.parametrize(
    "message",
    [
        "Exceeded maximum output retries (3)",
        "litellm.InternalServerError: Cannot connect to host 10.0.0.9:8888",
        "The context window is exceeded.",
    ],
)
def test_another_model_error_is_not_a_token_limit_stop(message: str) -> None:
    assert not is_token_limit_before_response(UnexpectedModelBehavior(message))


# ── what the retry sends ──────────────────────────────────────────────────────


async def test_the_retry_asks_the_gateway_for_low_reasoning(settings_kratos: Settings) -> None:
    """The real analyst model against a fake gateway. The retry settings put
    ``reasoning_effort`` in the request body and keep the token cap."""
    bodies: list[dict[str, Any]] = []

    def _handler(request: httpx.Request) -> httpx.Response:
        bodies.append(json.loads(request.content.decode()))
        return httpx.Response(
            200,
            json={
                "id": "c1",
                "object": "chat.completion",
                "created": 0,
                "model": "analyst",
                "choices": [
                    {
                        "index": 0,
                        "finish_reason": "stop",
                        "message": {"role": "assistant", "content": "ok"},
                    }
                ],
                "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2},
            },
        )

    with patch(
        "soc_ai.agent.models.RetryingAsyncTransport",
        lambda **_kw: httpx.MockTransport(_handler),
    ):
        model = build_synthesizer_model(settings_kratos)
        agent: Agent[None, str] = Agent(model)
        await agent.run("first")
        await agent.run("again", model_settings=low_reasoning_settings())

    assert "reasoning_effort" not in bodies[0]
    assert bodies[1]["reasoning_effort"] == LOW_REASONING_EFFORT
    cap = settings_kratos.synthesizer_max_response_tokens
    assert cap in (bodies[1].get("max_completion_tokens"), bodies[1].get("max_tokens"))


# ── one synthesis call ────────────────────────────────────────────────────────


async def test_a_synthesis_call_runs_once_more_with_low_reasoning() -> None:
    result = MagicMock()
    agent = MagicMock()
    agent.run = AsyncMock(side_effect=[_token_limit(), result])
    retried: list[dict[str, Any]] = []
    out = await orch._run_with_token_limit_retry(
        agent, "the prompt", turn_timeout_s=5, phase="synth_first_round1", retried=retried
    )
    assert out is result
    assert agent.run.await_count == 2
    first, second = agent.run.await_args_list
    assert first.args == ("the prompt",)
    assert "model_settings" not in first.kwargs
    assert second.args == ("the prompt",)
    assert second.kwargs["model_settings"] == low_reasoning_settings()
    assert retried == [
        {
            "phase": "synth_first_round1",
            "reasoning_effort": LOW_REASONING_EFFORT,
            "message": TOKEN_LIMIT,
        }
    ]


async def test_a_second_token_limit_stop_is_not_tried_again() -> None:
    """Negative control: the retry count is one. The second stop reaches the
    caller, which lands the fallback as before."""
    agent = MagicMock()
    agent.run = AsyncMock(side_effect=[_token_limit(), _token_limit(), MagicMock()])
    retried: list[dict[str, Any]] = []
    with pytest.raises(UnexpectedModelBehavior):
        await orch._run_with_token_limit_retry(
            agent, "p", turn_timeout_s=5, phase="synth_first_round1", retried=retried
        )
    assert agent.run.await_count == 2
    assert len(retried) == 1


async def test_another_error_gets_no_retry() -> None:
    """Negative control: a schema failure and a gateway error keep their path."""
    for exc in (
        UnexpectedModelBehavior("Exceeded maximum output retries (3)"),
        RuntimeError("litellm.InternalServerError: Cannot connect to host"),
    ):
        agent = MagicMock()
        agent.run = AsyncMock(side_effect=[exc, MagicMock()])
        retried: list[dict[str, Any]] = []
        with pytest.raises(type(exc)):
            await orch._run_with_token_limit_retry(
                agent, "p", turn_timeout_s=5, phase="synth_first_round1", retried=retried
            )
        assert agent.run.await_count == 1
        assert retried == []


def test_the_resume_history_ends_with_the_last_request() -> None:
    first = ModelRequest(parts=[UserPromptPart(content="investigate")])
    call = ModelResponse(parts=[ToolCallPart(tool_name="t_x", args={}, tool_call_id="1")])
    returned = ModelRequest(
        parts=[ToolReturnPart(tool_name="t_x", content={"total": 1}, tool_call_id="1")]
    )
    stopped = ModelResponse(parts=[ThinkingPart(content="a long thought")])
    assert orch._resume_history([first, call, returned, stopped]) == [first, call, returned]
    assert orch._resume_history([first, stopped]) == [first]
    assert orch._resume_history([]) == []


# ── the contract with pydantic-ai ─────────────────────────────────────────────


async def test_a_real_agent_resumes_from_the_history_with_low_reasoning() -> None:
    """The resume of the loop, on a real agent. A response that holds thinking
    only and ends at the token limit raises the token-limit error. The same
    agent then continues from the history before that response. It gets the
    low reasoning setting, it keeps the tool result, and no tool runs twice."""
    from pydantic_ai.models.function import AgentInfo, FunctionModel

    tool_runs: list[str] = []
    seen_effort: list[Any] = []

    def _model(messages: list[Any], info: AgentInfo) -> ModelResponse:
        effort = (info.model_settings or {}).get("openai_reasoning_effort")
        seen_effort.append(effort)
        returned = any(
            isinstance(part, ToolReturnPart)
            for message in messages
            for part in getattr(message, "parts", [])
        )
        if not returned:
            return ModelResponse(
                parts=[ToolCallPart(tool_name="lookup", args={"key": "a"}, tool_call_id="tc1")]
            )
        if effort != LOW_REASONING_EFFORT:
            # The model spends its whole budget on reasoning.
            return ModelResponse(
                parts=[ThinkingPart(content="a long thought")], finish_reason="length"
            )
        return ModelResponse(parts=[TextPart(content="the verdict")])

    agent: Agent[None, str] = Agent(FunctionModel(_model))

    @agent.tool_plain
    def lookup(key: str) -> str:
        tool_runs.append(key)
        return f"value of {key}"

    gathered: list[Any] = []

    async def _first_attempt() -> None:
        async with agent.iter("investigate") as run:
            async for node in run:
                message = getattr(node, "model_response", None) or getattr(node, "request", None)
                if message is not None:
                    gathered.append(message)

    with pytest.raises(UnexpectedModelBehavior) as stopped:
        await _first_attempt()
    assert is_token_limit_before_response(stopped.value)

    history = orch._resume_history(gathered)
    assert isinstance(history[-1], ModelRequest)
    async with agent.iter(
        None, message_history=history, model_settings=low_reasoning_settings()
    ) as resumed:
        nodes = [node async for node in resumed]
    assert resumed.result is not None
    assert resumed.result.output == "the verdict"
    assert tool_runs == ["a"]
    assert seen_effort[-1] == LOW_REASONING_EFFORT
    # The resumed run yields the last request of the history first. The loop
    # skips that one node, because its tool result streamed before the stop.
    requests = [n for n in nodes if getattr(n, "request", None) is not None]
    assert len(requests) == 1
    assert any(isinstance(p, ToolReturnPart) for p in requests[0].request.parts)

    # Review defect 10. The counters of the stopped attempt carry over, so the
    # request limit and the tool-call limit of the loop hold for the whole
    # run. The stopped attempt made two requests and one tool call.
    carried = RunUsage(requests=2, tool_calls=1)
    async with agent.iter(
        None,
        message_history=history,
        model_settings=low_reasoning_settings(),
        usage=carried,
    ) as counted:
        async for _node in counted:
            pass
    assert counted.usage().requests == 3
    assert counted.usage().tool_calls == 1
    # A limit of two requests is spent, so the resumed loop stops at once.
    from pydantic_ai.exceptions import UsageLimitExceeded

    with pytest.raises(UsageLimitExceeded):
        await _drain(
            agent.iter(
                None,
                message_history=history,
                model_settings=low_reasoning_settings(),
                usage=RunUsage(requests=2, tool_calls=1),
                usage_limits=UsageLimits(request_limit=2),
            )
        )


async def _drain(run_cm: Any) -> None:
    async with run_cm as run:
        async for _node in run:
            pass


# ── the pipeline ──────────────────────────────────────────────────────────────


class _StoppingIterCM:
    """An investigator run that streams its messages and then raises."""

    def __init__(self, messages: list[Any], exc: BaseException) -> None:
        self._messages = messages
        self._exc = exc

    async def __aenter__(self) -> Any:
        messages, exc = self._messages, self._exc

        class _Run:
            result = None

            def usage(self) -> Any:
                return STOPPED_USAGE

            def __aiter__(self) -> Any:
                async def _gen() -> Any:
                    for m in messages:
                        yield (
                            hs._FakeIterNode(m)
                            if isinstance(m, ModelResponse)
                            else MagicMock(model_response=None, request=m)
                        )
                    raise exc

                return _gen()

        return _Run()

    async def __aexit__(self, *_exc: Any) -> bool:
        return False


def _loop_messages() -> tuple[ModelRequest, ModelResponse, ModelRequest, ModelResponse]:
    first = ModelRequest(parts=[UserPromptPart(content="investigate the alert")])
    call = ModelResponse(
        parts=[
            ToolCallPart(
                tool_name="t_query_zeek_logs", args={"community_id": "1:abc"}, tool_call_id="tc1"
            )
        ]
    )
    returned = ModelRequest(
        parts=[
            ToolReturnPart(
                tool_name="t_query_zeek_logs",
                content={"kerberos": [{"_id": hs.ANCHOR_ID, "cipher": "rc4-hmac"}]},
                tool_call_id="tc1",
            )
        ]
    )
    stopped = ModelResponse(parts=[ThinkingPart(content="binary payload, long thought")])
    return first, call, returned, stopped


async def _run_loop(settings: Settings, investigator: Any, report: TriageReport) -> list[Any]:
    settings.investigate_when_unsure = True
    ctx = hs._make_ctx(settings)

    async def _stub_enriched(alert_id: str, **_kw: Any) -> Any:
        return hs._enriched(alert_id)

    with (
        patch(
            "soc_ai.tools.get_alert_context.get_enriched_alert_context",
            side_effect=_stub_enriched,
        ),
        patch(
            "soc_ai.agent.orchestrator.build_synthesizer_model",
            return_value=TestModel(call_tools=[]),
        ),
        patch("soc_ai.agent.orchestrator.build_investigator", return_value=investigator),
        patch(
            "soc_ai.agent.orchestrator.build_synthesizer",
            return_value=hs._fake_loop_synth(report),
        ),
        patch(
            "soc_ai.agent.decision_templates.match_decision_template",
            MagicMock(return_value=None),
        ),
        patch("soc_ai.store.investigations.session_verdicts", AsyncMock(return_value=[])),
        patch("soc_ai.agent.orchestrator.maybe_auto_ack_fp", AsyncMock(return_value=None)),
    ):
        return [ev async for ev in investigate(hs.ANCHOR_ID, ctx=ctx)]


def _report() -> TriageReport:
    return TriageReport(
        verdict="false_positive",
        confidence=0.85,
        summary="The ticket request is a normal service ticket.",
        citations=[hs.ANCHOR_ID],
        recommended_actions=[],
    )


def _resumed_run(first_messages: tuple[Any, ...]) -> Any:
    """The second investigator run: it yields the last request of the history
    again, then one final response, then a result."""
    _first, _call, returned, _stopped = first_messages
    final = ModelResponse(parts=[TextPart(content="done")])
    result = MagicMock()
    result.output = InvestigationTranscript(
        evidence=[f"t_query_zeek_logs -> rc4-hmac ticket (id={hs.ANCHOR_ID})"],
        tentative_summary="An RC4 service ticket was requested.",
        open_questions=[],
    )
    result.all_messages = MagicMock(return_value=[*first_messages[:3], final])
    result.usage = MagicMock(side_effect=RuntimeError("no usage in stub"))

    class _CM:
        async def __aenter__(self) -> Any:
            class _Run:
                def __aiter__(self) -> Any:
                    async def _gen() -> Any:
                        yield MagicMock(model_response=None, request=returned)
                        yield hs._FakeIterNode(final)

                    return _gen()

            run = _Run()
            run.result = result  # type: ignore[attr-defined]
            return run

        async def __aexit__(self, *_exc: Any) -> bool:
            return False

    return _CM()


async def test_the_loop_resumes_one_time_with_low_reasoning(settings_kratos: Settings) -> None:
    messages = _loop_messages()
    investigator = MagicMock()
    investigator.iter = MagicMock(
        side_effect=[_StoppingIterCM(list(messages), _token_limit()), _resumed_run(messages)]
    )
    events = await _run_loop(settings_kratos, investigator, _report())

    kinds = [e.kind for e in events]
    assert kinds.count("token_limit_retry") == 1
    retry = next(e.payload for e in events if e.kind == "token_limit_retry")
    assert retry["phase"] == "investigation_loop"
    assert retry["reasoning_effort"] == LOW_REASONING_EFFORT
    # The run reaches a verdict and records no error.
    assert "error" not in kinds
    final = next(e.payload for e in events if e.kind == "triage_report")
    assert final["verdict"] == "false_positive"

    assert investigator.iter.call_count == 2
    first_call, second_call = investigator.iter.call_args_list
    assert "model_settings" not in first_call.kwargs
    assert "message_history" not in first_call.kwargs
    # The resume: no new prompt, the history before the stopped turn, low reasoning.
    assert second_call.args == (None,)
    assert second_call.kwargs["message_history"] == list(messages[:3])
    assert second_call.kwargs["model_settings"] == low_reasoning_settings()
    # Review defect 10. The counters of the stopped attempt go into the
    # resumed loop, so its request limit and its tool-call limit do not start
    # again from zero. The stopped attempt writes no usage event of its own:
    # the usage of the resumed loop holds its counters.
    assert second_call.kwargs["usage"] is STOPPED_USAGE
    assert "usage" not in first_call.kwargs
    assert kinds.count("usage") == 0
    # The report carries the mark of the low reasoning retry.
    assert final["low_reasoning_retry"] == {"phases": ["investigation_loop"]}
    # No tool runs twice, and the tool result streams one time.
    assert kinds.count("tool_call") == 1
    assert kinds.count("tool_result") == 1


async def test_the_loop_does_not_resume_a_second_time(settings_kratos: Settings) -> None:
    """Negative control: a second token-limit stop ends the run with the error
    that it recorded before the fix."""
    messages = _loop_messages()
    investigator = MagicMock()
    investigator.iter = MagicMock(
        side_effect=[
            _StoppingIterCM(list(messages), _token_limit()),
            _StoppingIterCM([messages[2]], _token_limit()),
            _resumed_run(messages),
        ]
    )
    events = await _run_loop(settings_kratos, investigator, _report())
    kinds = [e.kind for e in events]
    assert investigator.iter.call_count == 2
    assert kinds.count("token_limit_retry") == 1
    error = next(e.payload for e in events if e.kind == "error")
    assert error["phase"] == "investigation_loop"
    assert "token limit" in error["message"].lower()
    assert "triage_report" not in kinds


async def test_a_gateway_error_in_the_loop_gets_no_retry(settings_kratos: Settings) -> None:
    """Negative control on the path the retry must not take: a gateway
    connection error stops the run at once."""
    messages = _loop_messages()
    investigator = MagicMock()
    investigator.iter = MagicMock(
        side_effect=[
            _StoppingIterCM(
                list(messages[:3]),
                RuntimeError("litellm.InternalServerError: Cannot connect to host"),
            ),
            _resumed_run(messages),
        ]
    )
    events = await _run_loop(settings_kratos, investigator, _report())
    kinds = [e.kind for e in events]
    assert investigator.iter.call_count == 1
    assert "token_limit_retry" not in kinds
    assert "error" in kinds


# ── the record ────────────────────────────────────────────────────────────────


def test_the_retry_event_is_an_audit_kind_with_a_title() -> None:
    payload = orch._token_limit_retry_payload("investigation_loop", _token_limit())
    AuditEvent(session_id="s", kind="token_limit_retry", payload=payload)
    title = label_event("token_limit_retry", payload)["title"]
    assert "output token limit" in title
    assert "low reasoning" in title


async def test_a_run_with_no_retry_carries_no_mark(settings_kratos: Settings) -> None:
    """Negative control: the key is absent, so every other report keeps its shape."""
    events, _spies = await hs._run(settings_kratos, subject=None, report=_report())
    final = next(e.payload for e in events if e.kind == "triage_report")
    assert "low_reasoning_retry" not in final
    assert not any(e.kind == "token_limit_retry" for e in events)


async def test_a_synthesis_retry_marks_the_report(settings_kratos: Settings) -> None:
    """The mark names each phase that ran again with low reasoning."""
    loop_synth = MagicMock()
    result = MagicMock()
    result.output = _report()
    result.usage = MagicMock(side_effect=RuntimeError("no usage in stub"))
    loop_synth.run = AsyncMock(side_effect=[_token_limit(), result])
    settings_kratos.investigate_when_unsure = True
    ctx = hs._make_ctx(settings_kratos)

    async def _stub_enriched(alert_id: str, **_kw: Any) -> Any:
        return hs._enriched(alert_id)

    with (
        patch(
            "soc_ai.tools.get_alert_context.get_enriched_alert_context",
            side_effect=_stub_enriched,
        ),
        patch(
            "soc_ai.agent.orchestrator.build_synthesizer_model",
            return_value=TestModel(call_tools=[]),
        ),
        patch("soc_ai.agent.orchestrator.build_investigator", return_value=hs._fake_investigator()),
        patch("soc_ai.agent.orchestrator.build_synthesizer", return_value=loop_synth),
        patch(
            "soc_ai.agent.decision_templates.match_decision_template",
            MagicMock(return_value=None),
        ),
        patch("soc_ai.store.investigations.session_verdicts", AsyncMock(return_value=[])),
        patch("soc_ai.agent.orchestrator.maybe_auto_ack_fp", AsyncMock(return_value=None)),
    ):
        events = [ev async for ev in investigate(hs.ANCHOR_ID, ctx=ctx)]
    final = next(e.payload for e in events if e.kind == "triage_report")
    assert final["low_reasoning_retry"] == {"phases": ["investigation_loop_synth"]}


def test_the_api_serves_the_low_reasoning_mark() -> None:
    from types import SimpleNamespace

    from soc_ai.api.webui import _timeline

    marked = {
        "verdict": "false_positive",
        "low_reasoning_retry": {"phases": ["investigation_loop"]},
    }
    assert _timeline._low_reasoning_of(marked, []) is True
    # A stored run with the event and no key on its report.
    event = SimpleNamespace(kind="token_limit_retry", payload={"phase": "synth_first_round1"})
    assert _timeline._low_reasoning_of({"verdict": "false_positive"}, [event]) is True
    # Negative control: a run with no retry.
    usage = SimpleNamespace(kind="usage", payload={})
    assert _timeline._low_reasoning_of({"verdict": "false_positive"}, [usage]) is False
