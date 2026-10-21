"""The swarm triage experiment: the strategies behind the investigation loop.

docs/dev/specs/2026-10-08-swarm-triage-experiment-design.md. One setting,
``investigator_strategy``, swaps the investigation loop of the synth-first
pipeline. ``single`` is the loop as it was. ``spend`` and ``ensemble`` are the
same loop under the limits of their arm. ``advocates`` and ``planes`` run the
swarm package: agents built through the investigator builder, each with its
own limits, in parallel, and a judge with no tools that writes the report.

The agents here are real pydantic-ai agents on a ``FunctionModel``. The model
function reads the mandate in the system prompt to know which agent it plays,
so the tests drive the real builders, the real tool registration and the real
usage accounting.
"""

from __future__ import annotations

from collections import Counter
from typing import Any
from unittest.mock import AsyncMock, patch

import pytest
from pydantic_ai.messages import (
    ModelMessage,
    ModelResponse,
    SystemPromptPart,
    ToolCallPart,
    ToolReturnPart,
    UserPromptPart,
)
from pydantic_ai.models.function import AgentInfo, FunctionModel
from soc_ai.agent import budget
from soc_ai.agent.context import StepEvent
from soc_ai.agent.evidence import _classify_citation
from soc_ai.agent.loop_result import LoopResult
from soc_ai.agent.orchestrator import InvestigationContext, investigate
from soc_ai.agent.swarm import SwarmInputs, run_strategy
from soc_ai.agent.swarm.briefs import Brief, BriefEvidence
from soc_ai.agent.swarm.judge import drop_foreign_citations
from soc_ai.agent.swarm.planes import plane_tools
from soc_ai.agent.swarm.runner import share_budget
from soc_ai.agent.triage import TriageReport
from soc_ai.config import Settings
from soc_ai.run_meter import OUTPUT_TOOL_NAME, RunMeter
from soc_ai.so_client.models import SoAlert
from soc_ai.tools.get_alert_context import EnrichedAlertContext

from tests.test_agent import _make_ctx

# An id-shaped alert id: the gates resolve a citation of it as a retrieved
# document, so only the swarm filter can take it off a judge's report.
_ALERT_ID = "AlertDoc0000000000001"
_THREAT_DOC = "ThreatDoc000000000001"
_BENIGN_DOC = "BenignDoc000000000001"
_PUBLIC_IP = "93.184.216.34"


# ── The model function ───────────────────────────────────────────────────────


def _prompt_text(messages: list[ModelMessage], info: AgentInfo) -> str:
    parts: list[str] = [info.instructions or ""]
    for message in messages:
        for part in getattr(message, "parts", []):
            if isinstance(part, SystemPromptPart | UserPromptPart):
                parts.append(str(part.content))
    return "\n".join(parts)


def _role_of(messages: list[ModelMessage], info: AgentInfo) -> str:
    text = _prompt_text(messages, info)
    if "Your tool budget is spent" in (info.instructions or ""):
        return "closer"
    if "## The briefs" in text:
        return "judge"
    if "## Your mandate: the threat advocate" in text:
        return "threat_advocate"
    if "## Your mandate: the benign advocate" in text:
        return "benign_advocate"
    for plane in (*sorted(budget.alert_planes(_flow_enriched())), "general", "payload"):
        if f"## Your mandate: the {plane} plane" in text:
            return f"plane_{plane}"
    return "unknown"


def _tool_returns(messages: list[ModelMessage]) -> int:
    return sum(
        1
        for message in messages
        for part in getattr(message, "parts", [])
        if isinstance(part, ToolReturnPart) and part.tool_name != OUTPUT_TOOL_NAME
    )


def _output(info: AgentInfo, args: dict[str, Any]) -> ModelResponse:
    return ModelResponse(parts=[ToolCallPart(info.output_tools[0].name, args)])


def _brief_args(claim: str, doc_id: str | None) -> dict[str, Any]:
    evidence = [{"document_id": doc_id, "line": f"{doc_id} shows the flow"}] if doc_id else []
    return {
        "claim": claim,
        "evidence": evidence,
        "counterpoint": "One record does not settle it.",
        "confidence": "medium" if doc_id else "none",
        "gaps": [],
    }


class _Swarm:
    """The FunctionModel behind every agent of one test, with a record of the calls."""

    def __init__(
        self,
        *,
        judge_citations: list[str] | None = None,
        fail_roles: frozenset[str] = frozenset(),
        endless_tools: bool = False,
    ) -> None:
        self.judge_citations = (
            judge_citations if judge_citations is not None else [_THREAT_DOC, _BENIGN_DOC]
        )
        self.fail_roles = fail_roles
        self.endless_tools = endless_tools
        self.calls: Counter[str] = Counter()
        self.tools_seen: dict[str, set[str]] = {}
        self.judge_prompts: list[str] = []

    def model(self) -> FunctionModel:
        return FunctionModel(self._respond, model_name="swarm-test")

    def _respond(self, messages: list[ModelMessage], info: AgentInfo) -> ModelResponse:
        role = _role_of(messages, info)
        self.calls[role] += 1
        self.tools_seen.setdefault(role, set()).update(t.name for t in info.function_tools)
        if role in self.fail_roles:
            raise RuntimeError(f"gateway refused the {role}")
        if role == "judge":
            self.judge_prompts.append(_prompt_text(messages, info))
            return _output(
                info,
                {
                    "verdict": "true_positive",
                    "confidence": 0.8,
                    "summary": "The threat brief holds. The benign brief names no service.",
                    "citations": self.judge_citations,
                    "recommended_actions": [],
                },
            )
        if role == "closer":
            return _output(info, _brief_args("The budget ran out.", None))
        names = {t.name for t in info.function_tools}
        returns = _tool_returns(messages)
        if "t_enrich_ip" in names and (self.endless_tools or returns == 0):
            return ModelResponse(
                parts=[ToolCallPart("t_enrich_ip", {"ip": f"93.184.216.{returns + 1}"})]
            )
        if role == "unknown":
            # The one investigator of the single loop writes the report itself.
            return _output(
                info,
                {
                    "verdict": "needs_more_info",
                    "confidence": 0.5,
                    "summary": "The one loop read the flow.",
                    "citations": ["(tool t_enrich_ip)"],
                    "recommended_actions": [],
                },
            )
        doc = {"threat_advocate": _THREAT_DOC, "benign_advocate": _BENIGN_DOC}.get(role)
        return _output(info, _brief_args(f"The {role} found a record.", doc))


# ── The pipeline driver ──────────────────────────────────────────────────────


def _flow_enriched(alert_id: str = _ALERT_ID) -> EnrichedAlertContext:
    """An outbound flow with a payload: the network, external and payload planes."""
    return EnrichedAlertContext(
        alert=SoAlert(
            id=alert_id,
            severity_label="medium",
            rule_name="ET POLICY Outbound test flow",
            source_ip="10.20.30.40",
            destination_ip=_PUBLIC_IP,
            network_community_id="1:swarmtestflow=",
            payload_printable="GET /index.html HTTP/1.1",
        ),
        community_id_events=[],
        host_events=[],
        user_events=[],
        process_events=[],
        file_events=[],
        pivot_summary={"community_id": 0, "host": 0, "user": 0, "process": 0, "file": 0},
    )


def _swarm_settings(settings: Settings, strategy: str) -> Settings:
    settings.investigator_strategy = strategy  # type: ignore[assignment]
    settings.investigator_emits_report = True
    return settings


async def _drive(
    settings: Settings,
    swarm: _Swarm,
    *,
    enriched_factory: Any = _flow_enriched,
) -> list[StepEvent]:
    ctx = _make_ctx(settings)
    # An analyst's run: the standard class, which always runs the loop.
    ctx.requested_run_class = "standard"

    async def _stub_enriched(aid: str, **_kw: Any) -> Any:
        return enriched_factory(aid)

    with (
        patch(
            "soc_ai.tools.get_alert_context.get_enriched_alert_context",
            side_effect=_stub_enriched,
        ),
        patch(
            "soc_ai.agent.orchestrator.build_synthesizer_model",
            return_value=swarm.model(),
        ),
        patch("soc_ai.agent.decision_templates.match_decision_template", return_value=None),
        patch("soc_ai.oracle.client.adjudicate", new=AsyncMock(return_value=None)),
    ):
        return [ev async for ev in investigate(_ALERT_ID, ctx=ctx)]


def _of(events: list[StepEvent], kind: str) -> list[dict[str, Any]]:
    return [e.payload for e in events if e.kind == kind]


def _report(events: list[StepEvent]) -> dict[str, Any]:
    return _of(events, "triage_report")[0]


def _finished(events: list[StepEvent]) -> dict[str, dict[str, Any]]:
    return {p["role"]: p for p in _of(events, "swarm_agent_finished")}


# ── The seam ─────────────────────────────────────────────────────────────────


async def test_single_never_reaches_the_swarm(settings_kratos: Settings) -> None:
    """The default strategy runs the one loop, and the report keeps its shape."""
    swarm = _Swarm()
    with patch("soc_ai.agent.swarm.run_strategy", side_effect=AssertionError("swarm ran")):
        events = await _drive(_swarm_settings(settings_kratos, "single"), swarm)
    report = _report(events)
    assert "strategy" not in report
    assert "swarm" not in report
    assert report["report_path"] == "investigator"
    assert not _of(events, "swarm_agent_started")


@pytest.mark.parametrize("strategy", ["spend", "ensemble"])
async def test_spend_and_ensemble_run_the_one_loop(
    settings_kratos: Settings, strategy: str
) -> None:
    """Arms B and C are settings. The loop is the single loop, and the report names the arm."""
    swarm = _Swarm()
    events = await _drive(_swarm_settings(settings_kratos, strategy), swarm)
    report = _report(events)
    assert report["strategy"] == strategy
    assert report["report_path"] == "investigator"
    assert "swarm" not in report
    assert not _of(events, "swarm_agent_started")


# ── Advocates ────────────────────────────────────────────────────────────────


async def test_advocates_write_two_briefs_and_one_judge_writes_the_report(
    settings_kratos: Settings,
) -> None:
    swarm = _Swarm()
    events = await _drive(_swarm_settings(settings_kratos, "advocates"), swarm)

    started = Counter(p["role"] for p in _of(events, "swarm_agent_started"))
    assert started == {"threat_advocate": 1, "benign_advocate": 1, "judge": 1}
    finished = _finished(events)
    assert finished["threat_advocate"]["status"] == "complete"
    assert finished["benign_advocate"]["status"] == "complete"
    assert finished["threat_advocate"]["brief"]["evidence"][0]["document_id"] == _THREAT_DOC
    assert finished["benign_advocate"]["brief"]["evidence"][0]["document_id"] == _BENIGN_DOC
    # One judge call: no agent runs twice on one alert.
    assert swarm.calls["judge"] == 1
    assert "## The briefs" in swarm.judge_prompts[0]

    report = _report(events)
    assert report["strategy"] == "advocates"
    assert report["report_path"] == "judge"
    assert report["swarm"]["agents"] == 3
    assert report["swarm"]["citations_dropped"] == 0
    # Every document id the report cites came from a brief.
    brief_ids = {_THREAT_DOC.lower(), _BENIGN_DOC.lower()}
    cited_ids = [
        target.lower()
        for kind, target in (_classify_citation(c) for c in report["citations"])
        if kind == "id" and target
    ]
    assert cited_ids
    assert set(cited_ids) <= brief_ids


async def test_an_advocate_that_raises_leaves_an_empty_brief_and_the_judge_reports(
    settings_kratos: Settings,
) -> None:
    swarm = _Swarm(fail_roles=frozenset({"benign_advocate"}), judge_citations=[_THREAT_DOC])
    events = await _drive(_swarm_settings(settings_kratos, "advocates"), swarm)

    finished = _finished(events)
    benign = finished["benign_advocate"]
    assert benign["status"] == "error"
    assert benign["brief"]["evidence"] == []
    assert "gateway refused the benign_advocate" in benign["brief"]["error"]
    assert finished["threat_advocate"]["status"] == "complete"
    # The judge saw the failure as a gap, and still wrote the report.
    assert swarm.calls["judge"] == 1
    assert "Error: this agent failed" in swarm.judge_prompts[0]
    report = _report(events)
    assert report["report_path"] == "judge"
    assert report["swarm"]["workers"][1]["status"] == "error"


async def test_the_usage_events_sum_to_the_tokens_of_all_three_agents(
    settings_kratos: Settings,
) -> None:
    swarm = _Swarm()
    events = await _drive(_swarm_settings(settings_kratos, "advocates"), swarm)

    finished = _finished(events)
    assert set(finished) == {"threat_advocate", "benign_advocate", "judge"}
    for role, payload in finished.items():
        assert payload["input_tokens"] > 0, role
        assert payload["requests"] >= 1, role
    usage = _of(events, "usage")
    for key in ("input_tokens", "output_tokens", "requests", "tool_calls"):
        assert sum(u[key] for u in usage) == sum(p[key] for p in finished.values()), key
    # Every usage event keeps the loop's shape, so the arms report reads it.
    for u in usage:
        assert {"phase", "round", "tool_calls", "requests", "input_tokens"} <= set(u)


async def test_the_advocates_never_exceed_the_tool_budget(settings_kratos: Settings) -> None:
    """Each advocate keeps calling tools. Each stops at its share and closes its brief."""
    settings_kratos.agent_tool_calls_limit = 4
    settings_kratos.advocate_tool_calls = 10
    swarm = _Swarm(endless_tools=True)
    events = await _drive(_swarm_settings(settings_kratos, "advocates"), swarm)

    shares = {p["role"]: p["tool_calls_limit"] for p in _of(events, "swarm_agent_started")}
    assert shares == {"threat_advocate": 2, "benign_advocate": 2, "judge": 0}
    finished = _finished(events)
    assert finished["threat_advocate"]["status"] == "limit"
    assert finished["benign_advocate"]["status"] == "limit"
    executed = [p for p in _of(events, "tool_result") if p.get("tool_name") != OUTPUT_TOOL_NAME]
    assert 0 < len(executed) <= 4
    assert sum(u["tool_calls"] for u in _of(events, "usage")) <= 4
    # The closer wrote each brief from the evidence gathered, with no tool.
    assert swarm.calls["closer"] == 2
    assert _report(events)["swarm"]["tool_calls"] <= 4


def test_the_budget_share_never_exceeds_the_total() -> None:
    assert share_budget(25, 2, 10) == 10
    assert share_budget(25, 9, 6) == 2
    assert share_budget(4, 2, 10) == 2
    assert share_budget(8, 9, 6) == 0
    for workers in range(1, 10):
        assert share_budget(25, workers, 6) * workers <= 25


async def test_the_run_meter_counts_every_agent(settings_kratos: Settings) -> None:
    swarm = _Swarm()
    events = await _drive(_swarm_settings(settings_kratos, "advocates"), swarm)

    meter = RunMeter()
    for ev in events:
        meter.observe(ev.kind, ev.payload)
    counters = meter.finish()
    finished = _finished(events)
    assert counters.input_tokens == sum(p["input_tokens"] for p in finished.values())
    assert counters.output_tokens == sum(p["output_tokens"] for p in finished.values())
    assert counters.model_requests == sum(p["requests"] for p in finished.values())
    tool_calls = [p for p in _of(events, "tool_call") if p.get("tool_name") != OUTPUT_TOOL_NAME]
    assert counters.tool_calls == len(tool_calls) >= 2
    # Each advocate's tool calls carry its role, so the trail tells them apart.
    assert {p["swarm_role"] for p in tool_calls} == {"threat_advocate", "benign_advocate"}


# ── The judge ────────────────────────────────────────────────────────────────


async def test_a_judge_citation_outside_the_briefs_is_dropped_and_counted(
    settings_kratos: Settings,
) -> None:
    """Negative control on the path the gates miss.

    The alert's own id is a retrieved document, so the citation gate resolves
    it. No brief carries it, so the judge may not cite it.
    """
    swarm = _Swarm(judge_citations=[_THREAT_DOC, _ALERT_ID, "alert.rule_name"])
    events = await _drive(_swarm_settings(settings_kratos, "advocates"), swarm)

    report = _report(events)
    assert _ALERT_ID not in report["citations"]
    assert _THREAT_DOC in report["citations"]
    # A field path is not a document id. It stays for the gates.
    assert "alert.rule_name" in report["citations"]
    assert report["swarm"]["citations_dropped"] == 1
    assert report["swarm"]["dropped_citations"] == [_ALERT_ID]
    assert _finished(events)["judge"]["citations_dropped"] == 1


def test_drop_foreign_citations_keeps_ids_the_briefs_carry() -> None:
    report = TriageReport(
        verdict="true_positive",
        confidence=0.8,
        summary="s",
        citations=[_THREAT_DOC.lower(), "(id OtherDoc0000000000009)", "t_enrich_ip", "prose"],
    )
    kept, dropped = drop_foreign_citations(report, [_THREAT_DOC])
    assert kept.citations == [_THREAT_DOC.lower(), "t_enrich_ip", "prose"]
    assert dropped == ["(id OtherDoc0000000000009)"]
    same, none = drop_foreign_citations(kept, [_THREAT_DOC])
    assert same is kept and none == []


def test_a_model_cannot_set_the_brief_error() -> None:
    from soc_ai.agent.swarm.briefs import model_brief

    brief = Brief(
        claim="c",
        evidence=[BriefEvidence(document_id="d", line="l")],
        error="the model wrote this",
    )
    assert model_brief(brief).error is None


# ── Planes ───────────────────────────────────────────────────────────────────


async def _run_planes(
    settings: Settings, swarm: _Swarm, enriched: EnrichedAlertContext
) -> tuple[LoopResult, list[StepEvent]]:
    from soc_ai.agent.orchestrator import StepEvent as _StepEvent

    settings.investigator_strategy = "planes"
    ctx: InvestigationContext = _make_ctx(settings)
    seq = [0]

    def make_ev(kind: str, payload: dict[str, Any]) -> _StepEvent:
        seq[0] += 1
        return _StepEvent(kind=kind, session_id="s", sequence=seq[0], payload=payload)

    loop = LoopResult(strategy="planes", emits_report=True)
    inputs = SwarmInputs(
        alert_id=enriched.alert.id,
        ctx=ctx,
        enriched=enriched,
        worker_msg="Investigate the alert.",
        context_msg="Investigate the alert.",
        trim_planes=None,
        guard=None,
        make_ev=make_ev,
    )
    with patch("soc_ai.agent.orchestrator.build_synthesizer_model", return_value=swarm.model()):
        events = [ev async for ev in run_strategy(loop, inputs)]
    return loop, events


async def test_one_worker_runs_per_plane_and_sees_only_its_tools(
    settings_kratos: Settings,
) -> None:
    enriched = _flow_enriched()
    planes = sorted(budget.alert_planes(enriched))
    assert planes == ["external", "network", "payload"]
    swarm = _Swarm(judge_citations=[])
    loop, events = await _run_planes(settings_kratos, swarm, enriched)

    started = [p for p in _of(events, "swarm_agent_started") if p["role"] != "lead"]
    assert [p["role"] for p in started] == [f"plane_{plane}" for plane in planes]
    for plane in planes:
        seen = swarm.tools_seen[f"plane_{plane}"]
        assert seen <= plane_tools(plane), plane
    # Each plane's own tools stay with its worker.
    assert "t_query_zeek_logs" in swarm.tools_seen["plane_network"]
    assert "t_query_zeek_logs" not in swarm.tools_seen["plane_payload"]
    assert "t_decode_payload" in swarm.tools_seen["plane_payload"]
    assert "t_decode_payload" not in swarm.tools_seen["plane_network"]
    assert "t_enrich_domain" in swarm.tools_seen["plane_external"]
    assert "t_enrich_domain" not in swarm.tools_seen["plane_network"]
    # No deferred loading: a worker cannot load another plane's tool.
    assert all("search_tools" not in seen for seen in swarm.tools_seen.values())
    assert swarm.calls["judge"] == 1
    assert loop.report_path == "lead"
    assert loop.counters["agents"] == len(planes) + 1


async def test_one_plane_means_one_worker(settings_kratos: Settings) -> None:
    enriched = EnrichedAlertContext(
        alert=SoAlert(id=_ALERT_ID, severity_label="low", payload_printable="USER anonymous"),
        community_id_events=[],
        host_events=[],
        user_events=[],
        process_events=[],
        file_events=[],
        pivot_summary={"community_id": 0, "host": 0, "user": 0, "process": 0, "file": 0},
    )
    assert budget.alert_planes(enriched) == frozenset({"payload"})
    swarm = _Swarm(judge_citations=[])
    loop, events = await _run_planes(settings_kratos, swarm, enriched)

    roles = [p["role"] for p in _of(events, "swarm_agent_started")]
    assert roles == ["plane_payload", "lead"]
    assert loop.counters["agents"] == 2
    # One worker gets its whole share: the setting, inside the total.
    assert _of(events, "swarm_agent_started")[0]["tool_calls_limit"] == 6


async def test_the_planes_share_the_tool_budget(settings_kratos: Settings) -> None:
    settings_kratos.agent_tool_calls_limit = 9
    swarm = _Swarm(judge_citations=[], endless_tools=True)
    loop, events = await _run_planes(settings_kratos, swarm, _flow_enriched())

    shares = [
        p["tool_calls_limit"] for p in _of(events, "swarm_agent_started") if p["role"] != "lead"
    ]
    assert shares == [3, 3, 3]
    assert sum(u["tool_calls"] for u in _of(events, "usage")) <= 9
    assert loop.counters["tool_calls"] <= 9


# ── The trail ────────────────────────────────────────────────────────────────


async def test_the_recorder_stores_the_swarm_events_and_counts_every_agent(
    settings_kratos: Settings,
) -> None:
    """The store keeps the two swarm event types, and the row costs every agent."""
    from soc_ai.api.recorder import InvestigationRecorder
    from soc_ai.store.db import make_engine, make_sessionmaker, run_migrations
    from soc_ai.store.models import Investigation, InvestigationEvent
    from sqlalchemy import select

    swarm = _Swarm()
    events = await _drive(_swarm_settings(settings_kratos, "advocates"), swarm)
    engine = make_engine(settings_kratos)
    await run_migrations(engine)
    maker = make_sessionmaker(engine)
    rec = InvestigationRecorder(maker, alert_id=_ALERT_ID, started_by="t")
    inv_id = await rec.start()
    assert inv_id is not None
    for ev in events:
        await rec.record(ev.kind, ev.sequence, ev.payload)
    await rec.finish("complete")
    async with maker() as db:
        row = await db.get(Investigation, inv_id)
        query = select(InvestigationEvent.kind).where(InvestigationEvent.investigation_id == inv_id)
        stored = Counter((await db.execute(query)).scalars().all())
    await engine.dispose()
    assert row is not None
    assert row.status == "complete"
    assert stored["swarm_agent_started"] == 3
    assert stored["swarm_agent_finished"] == 3
    finished = _finished(events)
    assert row.input_tokens == sum(p["input_tokens"] for p in finished.values())
    assert row.report is not None
    assert row.report["strategy"] == "advocates"


def test_the_timeline_titles_the_swarm_events() -> None:
    from soc_ai.webui.timeline_labels import label_event

    started = label_event(
        "swarm_agent_started",
        {"role": "threat_advocate", "label": "the threat advocate", "tool_calls_limit": 10},
    )
    assert started["title"] == "The threat advocate started with 10 tool calls"
    finished = label_event(
        "swarm_agent_finished", {"label": "the judge", "status": "complete", "tool_calls": 0}
    )
    assert finished["title"] == "The judge finished: 0 tool calls"
    cut = label_event(
        "swarm_agent_finished",
        {"label": "the network worker", "status": "limit", "tool_calls": 6},
    )
    assert cut["title"] == "The network worker stopped at its limit: 6 tool calls"
    assert label_event("swarm_agent_finished", {"role": "lead"})["title"] == "Lead finished"
