"""Prompt and tool schema trim per budget class (stage 1, item 5).

The loop prompt is 40,018 characters and the 26 investigator tool schemas add
about 7,000 tokens to every request. The standard class sends the sections and
the schemas the alert's planes make useful; every other tool stays registered
with deferred loading, one ``search_tools`` call away. The deep class keeps the
whole prompt and every schema. The cheap class sends no tool schema at all.

Measured with the pydantic-ai ``FunctionModel`` the suite uses, and on the wire
with the OpenAI chat model the product uses.
"""

from __future__ import annotations

import contextlib
import json
from typing import Any
from unittest.mock import AsyncMock

import httpx
from openai import AsyncOpenAI
from pydantic_ai.messages import (
    ModelMessage,
    ModelResponse,
    SystemPromptPart,
    ToolCallPart,
)
from pydantic_ai.models.function import AgentInfo, FunctionModel
from pydantic_ai.models.openai import OpenAIChatModel
from pydantic_ai.providers.openai import OpenAIProvider
from soc_ai.agent import budget
from soc_ai.agent.context import InvestigationContext
from soc_ai.agent.evidence import count_successful_tool_calls
from soc_ai.agent.orchestrator import build_investigator, build_synth_first_agent
from soc_ai.agent.prompts import build_investigator_prompt, format_more_tools_block
from soc_ai.config import Settings
from soc_ai.so_client.models import SoAlert
from soc_ai.tools.enrichment import IndicatorEnrichment
from soc_ai.tools.get_alert_context import EnrichedAlertContext

ALL_PLANES = frozenset(
    {
        budget.PLANE_NETWORK,
        budget.PLANE_EXTERNAL,
        budget.PLANE_EAST_WEST,
        budget.PLANE_WINDOWS,
        budget.PLANE_HOSTILE,
        budget.PLANE_PAYLOAD,
        budget.PLANE_FILE,
        budget.PLANE_ICMP,
        budget.PLANE_DECOY,
    }
)


def _flow_alert() -> EnrichedAlertContext:
    """A flow from the estate to the internet under an informational rule."""
    return EnrichedAlertContext(
        alert=SoAlert(
            id="flow-1",
            rule_name="ET INFO Observed TLS SNI to a rare domain",
            source_ip="10.20.0.5",
            destination_ip="203.0.113.7",
            severity_label="low",
        ),
        enrichments={
            "203.0.113.7": IndicatorEnrichment(
                indicator="203.0.113.7", indicator_type="ip", internal=False
            )
        },
    )


def _host_alert() -> EnrichedAlertContext:
    """A host-log detection with no flow."""
    return EnrichedAlertContext(
        alert=SoAlert(
            id="host-1",
            rule_name="Active Directory Replication from Non Machine Account",
            severity_label="high",
            event_module="windows",
            event_dataset="windows.security",
            host_name="dc-01.example.test",
        )
    )


# ── Planes ───────────────────────────────────────────────────────────────────


def test_a_flow_to_the_internet_is_network_and_external_only() -> None:
    planes = budget.alert_planes(_flow_alert())
    assert planes == {budget.PLANE_NETWORK, budget.PLANE_EXTERNAL}


def test_a_host_log_detection_is_windows_and_hostile() -> None:
    planes = budget.alert_planes(_host_alert())
    assert budget.PLANE_WINDOWS in planes
    assert budget.PLANE_HOSTILE in planes
    assert budget.PLANE_NETWORK not in planes


def test_an_east_west_attack_signature_keeps_the_windows_section() -> None:
    """Negative control: a lateral-movement signature on an internal flow."""
    enriched = EnrichedAlertContext(
        alert=SoAlert(
            id="lat-1",
            rule_name="ET POLICY SMB2 NT Create AndX Request For an Executable File",
            source_ip="10.20.0.5",
            destination_ip="10.20.0.9",
            severity_label="medium",
        )
    )
    planes = budget.alert_planes(enriched)
    assert budget.PLANE_EAST_WEST in planes
    assert budget.PLANE_WINDOWS in planes


def test_a_wmi_remote_execution_flow_keeps_the_windows_section() -> None:
    """The stage 1 eval case: an informational east-west rule that names WMI.

    Nothing on the alert said Windows. The rule name must, or the loop runs
    without the lateral-movement section. The control at the end: the same
    informational flow with a plain rule name stays off the Windows plane.
    """
    enriched = EnrichedAlertContext(
        alert=SoAlert(
            id="wmi-1",
            rule_name="SOC-AI ANALYTIC WMI Remote Method Invocation Observed",
            source_ip="10.20.0.5",
            destination_ip="10.20.0.9",
            severity_label="informational",
        )
    )
    planes = budget.alert_planes(enriched)
    assert budget.PLANE_EAST_WEST in planes
    assert budget.PLANE_WINDOWS in planes

    plain = EnrichedAlertContext(
        alert=SoAlert(
            id="plain-1",
            rule_name="SOC-AI ANALYTIC Internal Port Scan Observed",
            source_ip="10.20.0.5",
            destination_ip="10.20.0.9",
            severity_label="informational",
        )
    )
    assert budget.PLANE_WINDOWS not in budget.alert_planes(plain)


def test_a_dce_rpc_pivot_lights_the_windows_plane() -> None:
    """The alert says nothing about Windows, but its own session carried DCE-RPC."""
    from soc_ai.enrichment.zeek_parser import TypedZeekFields

    enriched = EnrichedAlertContext(
        alert=SoAlert(
            id="rpc-1",
            rule_name="SOC-AI ANALYTIC Unusual Internal Service Call",
            source_ip="10.20.0.5",
            destination_ip="10.20.0.9",
            severity_label="informational",
        ),
        typed_zeek=TypedZeekFields(dce_rpc_endpoints=["IWbemServices"]),
    )
    assert budget.PLANE_WINDOWS in budget.alert_planes(enriched)


def test_a_plane_fault_turns_every_plane_on() -> None:
    class Broken:
        @property
        def alert(self) -> Any:
            raise RuntimeError("boom")

    assert budget.alert_planes(Broken()) == ALL_PLANES


# ── The prompt ───────────────────────────────────────────────────────────────


def test_every_plane_on_is_the_whole_prompt_byte_for_byte() -> None:
    every_tool = frozenset({"t_get_pcap", "t_decode_payload"})
    for emits in (True, False):
        assert build_investigator_prompt(
            emits_report=emits, planes=ALL_PLANES, visible_tools=every_tool
        ) == build_investigator_prompt(emits_report=emits)


def test_a_flow_only_alert_gets_no_windows_section() -> None:
    planes = budget.alert_planes(_flow_alert())
    trimmed = build_investigator_prompt(
        emits_report=True, planes=planes, visible_tools=budget.standard_visible_tools(planes)
    )
    full = build_investigator_prompt(emits_report=True)
    assert len(trimmed) < len(full)
    assert "Internal-to-internal is NOT exculpatory" not in trimmed
    assert "### 11. Kerberoasting" not in trimmed
    assert "A decoy has no benign baseline" not in trimmed
    # The flow keeps what a flow needs.
    assert "Pivot via `network.community_id`" in trimmed
    assert "Research an external indicator" in trimmed
    assert "A reputation hit plus a completed connection" in trimmed


def test_a_host_log_alert_drops_the_flow_sections() -> None:
    planes = budget.alert_planes(_host_alert())
    trimmed = build_investigator_prompt(
        emits_report=True, planes=planes, visible_tools=budget.standard_visible_tools(planes)
    )
    assert "Pivot via `network.community_id`" not in trimmed
    assert "Internal-to-internal is NOT exculpatory" in trimmed
    assert "### 11. Kerberoasting" in trimmed
    # The steps that remain are numbered from 1 with no gap.
    rubric = trimmed[trimmed.find("## Investigation rubric") :]
    assert "1. **Read the pre-loaded alert context.**" in rubric
    assert "2. **Enrich external IPs" in rubric


# ── The request, per class ───────────────────────────────────────────────────


def _settings(base: Settings) -> Settings:
    # Every gated investigator tool on, so deep is the full surface.
    return base.model_copy(
        update={
            "web_search_enabled": True,
            "searxng_url": "https://search.example.test",
            "crawl4ai_enabled": True,
            "crawl4ai_url": "https://crawl.example.test",
            "pcap_enabled": True,
            "allow_online_enrichment": True,
        }
    )


def _ctx(settings: Settings, visible: frozenset[str] | None) -> InvestigationContext:
    return InvestigationContext(
        settings=settings,
        auth=AsyncMock(),
        elastic=AsyncMock(),
        loop_visible_tools=visible,
    )


def _measuring_model(sizes: dict[str, Any]) -> FunctionModel:
    """Record what one request carries: the system prompt and the tool schemas sent."""

    def respond(messages: list[ModelMessage], info: AgentInfo) -> ModelResponse:
        prompt = "".join(
            p.content
            for m in messages
            for p in getattr(m, "parts", [])
            if isinstance(p, SystemPromptPart)
        )
        sent = [t for t in info.function_tools if not t.defer_loading]
        sizes["tools"] = sorted(t.name for t in sent)
        sizes["schema_chars"] = sum(
            len(json.dumps(t.parameters_json_schema)) + len(t.description or "") for t in sent
        )
        sizes["prompt_chars"] = len(prompt)
        out = info.output_tools[0]
        return ModelResponse(
            parts=[
                ToolCallPart(
                    tool_name=out.name,
                    args={
                        "verdict": "false_positive",
                        "confidence": 0.8,
                        "summary": "x",
                        "citations": ["alert.rule_name"],
                        "recommended_actions": [],
                    },
                )
            ]
        )

    return FunctionModel(respond)


async def _request_sizes(settings: Settings, cls: str) -> dict[str, Any]:
    sizes: dict[str, Any] = {}
    model = _measuring_model(sizes)
    if cls == "cheap":
        agent: Any = build_synth_first_agent(model)
    else:
        planes = budget.alert_planes(_flow_alert())
        visible = budget.standard_visible_tools(planes) if cls == "standard" else None
        ctx = _ctx(settings, visible)
        prompt = (
            build_investigator_prompt(emits_report=True, planes=planes, visible_tools=visible)
            if cls == "standard"
            else None
        )
        agent = build_investigator(model, ctx, emits_report=True, system_prompt=prompt)
    await agent.run("Triage alert flow-1.")
    return sizes


async def test_the_request_shrinks_from_deep_to_standard_to_cheap(
    settings_kratos: Settings,
) -> None:
    settings = _settings(settings_kratos)
    deep = await _request_sizes(settings, "deep")
    standard = await _request_sizes(settings, "standard")
    cheap = await _request_sizes(settings, "cheap")
    # Deep keeps every investigator schema: 26 on production, plus the
    # playbook reader this test's settings register.
    assert len(deep["tools"]) >= 26
    # Standard sends the tools a flow to the internet makes useful.
    visible = budget.standard_visible_tools(budget.alert_planes(_flow_alert()))
    assert set(standard["tools"]) == visible & set(deep["tools"])
    assert len(standard["tools"]) < len(deep["tools"])
    assert standard["schema_chars"] < deep["schema_chars"] * 0.7
    assert standard["prompt_chars"] < deep["prompt_chars"]
    # Cheap sends no read tool schema at all.
    assert cheap["tools"] == []
    assert cheap["schema_chars"] == 0


async def test_a_deferred_tool_is_one_search_away(settings_kratos: Settings) -> None:
    """The standard loop loads a tool it does not see, and the load is no evidence."""
    settings = _settings(settings_kratos)
    planes = budget.alert_planes(_flow_alert())
    ctx = _ctx(settings, budget.standard_visible_tools(planes))
    turns: list[list[str]] = []

    def respond(messages: list[ModelMessage], info: AgentInfo) -> ModelResponse:
        turns.append(sorted(t.name for t in info.function_tools if not t.defer_loading))
        if len(turns) == 1:
            return ModelResponse(
                parts=[
                    ToolCallPart(tool_name="search_tools", args={"queries": ["t_describe_dataset"]})
                ]
            )
        if len(turns) == 2:
            return ModelResponse(
                parts=[ToolCallPart(tool_name="t_describe_dataset", args={"dataset": "zeek.conn"})]
            )
        return ModelResponse(
            parts=[
                ToolCallPart(
                    tool_name=info.output_tools[0].name,
                    args={
                        "verdict": "needs_more_info",
                        "confidence": 0.4,
                        "summary": "x",
                        "citations": [],
                        "recommended_actions": [],
                    },
                )
            ]
        )

    agent = build_investigator(FunctionModel(respond), ctx, emits_report=True)
    result = await agent.run("Triage alert flow-1.")
    assert "t_describe_dataset" in ctx.deferred_tool_names
    assert "t_describe_dataset" not in turns[0]
    assert "t_describe_dataset" in turns[2]
    called = [
        p.tool_name
        for m in result.all_messages()
        for p in getattr(m, "parts", [])
        if isinstance(p, ToolCallPart)
    ]
    assert "t_describe_dataset" in called
    # Loading a tool reads nothing about the alert. Only the dataset read counts.
    loader_only = [
        m
        for m in result.all_messages()
        if any(getattr(p, "tool_name", None) == "search_tools" for p in getattr(m, "parts", []))
    ]
    assert count_successful_tool_calls(loader_only) == 0


def test_the_more_tools_line_names_what_is_deferred() -> None:
    block = format_more_tools_block(["t_get_pcap", "t_lookup_runbook"])
    assert "`t_get_pcap`" in block and "`search_tools`" in block
    assert format_more_tools_block([]) == ""


async def test_the_wire_carries_the_trimmed_schema_list(settings_kratos: Settings) -> None:
    """The OpenAI chat model the product uses drops a deferred schema from the request."""
    settings = _settings(settings_kratos)
    bodies: list[dict[str, Any]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        bodies.append(json.loads(request.content))
        return httpx.Response(
            200,
            json={
                "id": "x",
                "object": "chat.completion",
                "created": 0,
                "model": "m",
                "choices": [
                    {
                        "index": 0,
                        "message": {"role": "assistant", "content": "{}"},
                        "finish_reason": "stop",
                    }
                ],
                "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2},
            },
        )

    def model() -> OpenAIChatModel:
        client = AsyncOpenAI(
            base_url="http://llm.example.test/v1",
            api_key="x",
            http_client=httpx.AsyncClient(transport=httpx.MockTransport(handler)),
        )
        return OpenAIChatModel("m", provider=OpenAIProvider(openai_client=client))

    planes = budget.alert_planes(_flow_alert())
    standard = build_investigator(
        model(), _ctx(settings, budget.standard_visible_tools(planes)), emits_report=False
    )
    deep = build_investigator(model(), _ctx(settings, None), emits_report=False)
    for agent in (standard, deep):
        # The canned reply is no transcript. The request already went out.
        with contextlib.suppress(Exception):
            await agent.run("Triage alert flow-1.")
    standard_tools = {t["function"]["name"] for t in bodies[0]["tools"]}
    deep_tools = {t["function"]["name"] for t in bodies[-1]["tools"]}
    assert "search_tools" in standard_tools
    assert "t_lookup_runbook" not in standard_tools
    assert "t_lookup_runbook" in deep_tools
    # The not-found hint of t_get_rule_content names it. Deferred, it cost a
    # search_tools round trip on each rule that was not found.
    assert "t_query_detections" in standard_tools
    assert len(json.dumps(bodies[0]["tools"])) < len(json.dumps(bodies[-1]["tools"]))


# ── The hint of a deferred tool ──────────────────────────────────────────────


async def test_the_tool_the_rule_content_hint_names_is_visible_in_standard(
    settings_kratos: Settings,
) -> None:
    """A rule that is not found tells the model to search with
    ``t_query_detections``. The standard class deferred that tool, so each such
    case cost one ``search_tools`` round trip. 6 of the 8 ``search_tools``
    calls on the range eval of 2026-10-05 loaded it."""
    import re
    from types import SimpleNamespace

    from soc_ai.tools.get_rule_content import get_rule_content

    elastic = AsyncMock()
    elastic.search.return_value = SimpleNamespace(hits=[])
    out = await get_rule_content("2054989", elastic=elastic, settings=settings_kratos)
    assert out["found"] is False
    named = set(re.findall(r"\bt_[a-z_]+", out["hint"]))
    assert named == {"t_query_detections"}
    for planes in (
        frozenset(),
        budget.alert_planes(_flow_alert()),
        budget.alert_planes(_host_alert()),
    ):
        assert named <= budget.standard_visible_tools(planes), planes
    # Negative control: the standard class still defers tools. A runbook
    # lookup stays one search_tools call away.
    assert "t_lookup_runbook" not in budget.standard_visible_tools(frozenset())
