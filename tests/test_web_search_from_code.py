"""The web search the loop used to spend its turn on now runs in code (stage 1, item 4).

The survey of 2026-10-04 found 87% of production loops spend their one tool
turn on ``t_web_search``, on a condition the code already computes: an
external indicator the prefetch enrichment left unanswered. The pipeline now
makes that call before the loop and hands the loop the result.

The loop here is a pydantic-ai ``FunctionModel`` that obeys the prompt: it
calls ``t_web_search`` only when the conditional-tool block tells it to. The
run counters measure what happened.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import AsyncMock, patch

from pydantic_ai.messages import ModelMessage, ModelResponse, ToolCallPart, UserPromptPart
from pydantic_ai.models.function import AgentInfo, FunctionModel
from soc_ai.agent.orchestrator import investigate
from soc_ai.config import Settings
from soc_ai.run_meter import RunMeter
from soc_ai.so_client.models import SoAlert
from soc_ai.tools.enrichment import IndicatorEnrichment
from soc_ai.tools.get_alert_context import EnrichedAlertContext

from tests.test_agent import _make_ctx

SRC, EXTERNAL = "192.0.2.10", "203.0.113.7"
CONDITION_LINE = "Call `t_web_search` on that indicator once"

_SEARCH_HIT = {
    "ok": True,
    "query": EXTERNAL,
    "result_count": 1,
    "results": [
        {
            "title": "203.0.113.7 reputation",
            "url": "https://reputation.example.test/203.0.113.7",
            "content": "A content delivery node. No abuse reports.",
            "engine": "searx",
        }
    ],
    "answers": [],
}


def _enriched(alert_id: str = "alert-ws") -> EnrichedAlertContext:
    return EnrichedAlertContext(
        alert=SoAlert(
            id=alert_id,
            rule_name="ET INFO Observed TLS SNI to a rare domain",
            source_ip=SRC,
            destination_ip=EXTERNAL,
            severity_label="low",
        ),
        enrichments={
            EXTERNAL: IndicatorEnrichment(indicator=EXTERNAL, indicator_type="ip", internal=False)
        },
    )


def _user_text(messages: list[ModelMessage]) -> str:
    parts: list[str] = []
    for msg in messages:
        for part in getattr(msg, "parts", []) or []:
            if isinstance(part, UserPromptPart) and isinstance(part.content, str):
                parts.append(part.content)
    return "\n".join(parts)


def _obedient_loop(seen_prompts: list[str]) -> FunctionModel:
    """A loop model that calls ``t_web_search`` only when the prompt tells it to."""

    def respond(messages: list[ModelMessage], info: AgentInfo) -> ModelResponse:
        text = _user_text(messages)
        seen_prompts.append(text)
        already_called = any(
            isinstance(p, ToolCallPart) and p.tool_name == "t_web_search"
            for m in messages
            for p in getattr(m, "parts", []) or []
        )
        if CONDITION_LINE in text and not already_called:
            return ModelResponse(
                parts=[ToolCallPart(tool_name="t_web_search", args={"query": EXTERNAL})]
            )
        output_tool = info.output_tools[0].name
        return ModelResponse(
            parts=[
                ToolCallPart(
                    tool_name=output_tool,
                    args={
                        "verdict": "false_positive",
                        "confidence": 0.82,
                        "summary": "The destination is a content delivery node.",
                        "citations": ["(tool t_web_search)"],
                        "recommended_actions": [],
                    },
                )
            ]
        )

    return FunctionModel(respond)


async def _run(settings: Settings, search: Any) -> tuple[list[Any], list[str], AsyncMock]:
    settings.web_search_enabled = True
    settings.searxng_url = "https://search.example.test"
    settings.investigator_emits_report = True
    ctx = _make_ctx(settings)
    prompts: list[str] = []
    web = AsyncMock(side_effect=search)

    async def _stub_enriched(aid: str, **_kw: Any) -> Any:
        return _enriched(aid)

    with (
        patch(
            "soc_ai.tools.get_alert_context.get_enriched_alert_context",
            side_effect=_stub_enriched,
        ),
        patch(
            "soc_ai.agent.orchestrator.build_synthesizer_model",
            return_value=_obedient_loop(prompts),
        ),
        patch("soc_ai.agent.decision_templates.match_decision_template", return_value=None),
        # The pipeline's call and the loop's tool reach the same search function.
        patch("soc_ai.tools.web_search.web_search", web),
        patch("soc_ai.agent.toolset.web_search", web),
    ):
        events = [ev async for ev in investigate("alert-ws", ctx=ctx)]
    return events, prompts, web


def _meter(events: list[Any]) -> Any:
    meter = RunMeter()
    for ev in events:
        meter.observe(ev.kind, ev.payload)
    return meter.finish()


def _loop_web_calls(events: list[Any]) -> int:
    return sum(
        1
        for ev in events
        if ev.kind == "tool_call" and ev.payload.get("tool_name") == "t_web_search"
    )


async def test_the_loop_skips_the_search_the_prefetch_already_ran(
    settings_kratos: Settings,
) -> None:
    async def search(query: str, **_kw: Any) -> dict[str, Any]:
        return dict(_SEARCH_HIT, query=query)

    events, prompts, web = await _run(settings_kratos, search)
    # The pipeline searched once, in code, for the unresolved indicator.
    assert web.await_count == 1
    assert web.await_args is not None
    assert web.await_args.kwargs["query"] == EXTERNAL
    dispatch = next(e for e in events if e.kind == "targeted_dispatch")
    assert dispatch.payload["phase"] == "prefetch"
    assert dispatch.payload["tool_name"] == "t_web_search"
    # The loop was told the result and was not told to search.
    assert prompts and CONDITION_LINE not in prompts[0]
    assert "Web search already run" in prompts[0]
    # Measured: no web-search tool call from the loop, one tool call in all,
    # and one model request where the loop used to make two.
    assert _loop_web_calls(events) == 0
    counted = _meter(events)
    assert counted.tool_calls == 1
    assert counted.model_requests == 1
    # The search is the run's evidence, as the loop's own call was: the
    # evidence gate leaves the cited false positive standing.
    report = next(e for e in events if e.kind == "triage_report").payload
    assert report["verdict"] == "false_positive"
    assert "evidence_gate_downgrade" not in [e.kind for e in events]


async def test_the_loop_still_searches_when_the_prefetch_search_failed(
    settings_kratos: Settings,
) -> None:
    """Negative control: a failed search is no answer, so the loop keeps its turn."""
    calls: list[str] = []

    async def search(query: str, **_kw: Any) -> dict[str, Any]:
        calls.append(query)
        if len(calls) == 1:
            return {"ok": False, "error": "ConnectTimeout"}
        return dict(_SEARCH_HIT, query=query)

    events, prompts, web = await _run(settings_kratos, search)
    assert web.await_count == 2
    assert CONDITION_LINE in prompts[0]
    assert "Web search already run" not in prompts[0]
    assert _loop_web_calls(events) == 1
    counted = _meter(events)
    # The failed dispatch and the loop's own call.
    assert counted.tool_calls == 2
    assert counted.model_requests == 2


async def test_no_unresolved_indicator_means_no_search(settings_kratos: Settings) -> None:
    """An answered indicator needs no search, in code or in the loop."""
    answered = _enriched()
    answered.enrichments[EXTERNAL].asn = 64500

    async def search(query: str, **_kw: Any) -> dict[str, Any]:
        return dict(_SEARCH_HIT, query=query)

    with patch("tests.test_web_search_from_code._enriched", return_value=answered):
        events, prompts, web = await _run(settings_kratos, search)
    assert web.await_count == 0
    assert "targeted_dispatch" not in [e.kind for e in events]
    assert CONDITION_LINE not in prompts[0]
