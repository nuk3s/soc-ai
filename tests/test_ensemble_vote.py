"""Arm C of the swarm triage experiment: the vote on the W3 report path.

docs/dev/specs/2026-10-08-swarm-triage-experiment-design.md. The ``ensemble``
arm is the single loop with ``verdict_consistency_samples=3`` and
``agent_tool_calls_limit=8``. With ``investigator_emits_report`` on, the loop
writes the report, so the vote re-runs the loop itself, tools and all. A
strict majority of the three reports wins. A three-way split is
``inconclusive``. Each sample is a model run, and its usage event joins the
run, so the arms report counts the cost of all three.

At 8 tool calls a run often stops at its budget. Such a run votes with its
partial verdict: the partial synthesis writes it in one more call with no
tools, the way the primary loop lands a budget cut. Only a run that raises,
or that ends with no verdict, is dropped. The vote event states how many runs
voted, how many of the votes were partial and how many runs were dropped.
"""

from __future__ import annotations

from collections import Counter
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

from pydantic_ai.messages import ModelMessage, ModelResponse, ToolCallPart, ToolReturnPart
from pydantic_ai.models.function import AgentInfo, FunctionModel
from pydantic_ai.usage import RunUsage
from soc_ai.agent.context import StepEvent
from soc_ai.agent.orchestrator import investigate
from soc_ai.agent.triage import TriageReport
from soc_ai.config import Settings

from tests.test_agent import (
    _fake_loop_investigator_with_zeek_call,
    _make_ctx,
    _stub_enriched_alert_context,
)


def _of(events: list[StepEvent], kind: str) -> list[dict[str, Any]]:
    return [e.payload for e in events if e.kind == kind]


def _report(events: list[StepEvent]) -> dict[str, Any]:
    return _of(events, "triage_report")[0]


def _w3_report(verdict: str, confidence: float) -> TriageReport:
    return TriageReport(
        verdict=verdict,  # type: ignore[arg-type]
        confidence=confidence,
        summary=f"The loop reads the flow as {verdict}.",
        citations=["(tool t_query_zeek_logs)"],
        recommended_actions=[],
    )


async def _drive_ensemble(
    settings: Settings, primary: TriageReport, samples: list[TriageReport]
) -> tuple[list[StepEvent], MagicMock]:
    settings.investigator_strategy = "ensemble"
    settings.investigator_emits_report = True
    settings.verdict_consistency_samples = 3
    settings.agent_tool_calls_limit = 8
    ctx = _make_ctx(settings)
    ctx.requested_run_class = "standard"
    investigator = _fake_loop_investigator_with_zeek_call()
    investigator.iter.return_value._run.result.output = primary

    def _sample(report: TriageReport) -> Any:
        return SimpleNamespace(
            output=report,
            usage=RunUsage(requests=2, tool_calls=1, input_tokens=100, output_tokens=10),
        )

    investigator.run = AsyncMock(side_effect=[_sample(r) for r in samples])

    async def _stub_enriched(aid: str, **_kw: Any) -> Any:
        return _stub_enriched_alert_context(aid)

    with (
        patch(
            "soc_ai.tools.get_alert_context.get_enriched_alert_context",
            side_effect=_stub_enriched,
        ),
        patch("soc_ai.agent.orchestrator.build_synthesizer_model", return_value=object()),
        patch("soc_ai.agent.orchestrator.build_investigator", return_value=investigator),
        patch("soc_ai.agent.decision_templates.match_decision_template", return_value=None),
        patch("soc_ai.oracle.client.adjudicate", new=AsyncMock(return_value=None)),
    ):
        events = [ev async for ev in investigate("alert-001", ctx=ctx)]
    return events, investigator


async def test_ensemble_reaches_a_majority_on_the_w3_path(settings_kratos: Settings) -> None:
    events, investigator = await _drive_ensemble(
        settings_kratos,
        _w3_report("true_positive", 0.8),
        [_w3_report("true_positive", 0.7), _w3_report("false_positive", 0.9)],
    )
    # Two more runs of the loop itself, each under the arm's 8-call budget.
    assert investigator.run.await_count == 2
    for call in investigator.run.await_args_list:
        assert call.kwargs["usage_limits"].tool_calls_limit == 8
    vote = _of(events, "self_consistency_vote")[0]
    assert vote["samples"] == 3
    assert vote["tally"] == {"true_positive": 2, "false_positive": 1}
    assert vote["chosen_verdict"] == "true_positive"
    assert _report(events)["report_path"] == "investigator"
    # The two samples are model runs, and the arms report counts them.
    samples = [u for u in _of(events, "usage") if "self_consistency_sample" in u]
    assert [u["input_tokens"] for u in samples] == [100, 100]


async def test_an_ensemble_three_way_split_is_inconclusive(settings_kratos: Settings) -> None:
    events, _investigator = await _drive_ensemble(
        settings_kratos,
        _w3_report("true_positive", 0.8),
        [_w3_report("false_positive", 0.7), _w3_report("needs_more_info", 0.5)],
    )
    vote = _of(events, "self_consistency_vote")[0]
    assert vote["chosen_verdict"] == "inconclusive"
    assert _report(events)["verdict"] == "inconclusive"
    assert _report(events)["confidence"] <= 0.5


# ── Runs cut at the budget vote ──────────────────────────────────────────────

# A run plan: "budget" calls a tool on every turn until the 8-call budget stops
# it, "raise" fails the run, and a verdict word writes that report.
_BUDGET = "budget"
_RAISE = "raise"


def _report_args(verdict: str, confidence: float) -> dict[str, Any]:
    return {
        "verdict": verdict,
        "confidence": confidence,
        "summary": f"The run reads the flow as {verdict}.",
        "citations": ["(tool t_enrich_ip)"],
        "recommended_actions": [],
    }


class _ArmC:
    """The FunctionModel behind the real loop and the real partial synthesis.

    Each investigator run follows the next plan in ``runs``. The partial
    synthesis, which has no tools, writes the next verdict in ``partials``.
    """

    def __init__(self, runs: list[str], partials: list[str]) -> None:
        self.runs = list(runs)
        self.partials = list(partials)
        self.run_index = -1
        self.calls: Counter[str] = Counter()

    def model(self) -> FunctionModel:
        return FunctionModel(self._respond, model_name="arm-c-test")

    def _respond(self, messages: list[ModelMessage], info: AgentInfo) -> ModelResponse:
        output = info.output_tools[0].name
        if not info.function_tools:
            self.calls["partial"] += 1
            verdict = self.partials.pop(0)
            return ModelResponse(parts=[ToolCallPart(output, _report_args(verdict, 0.9))])
        if len(messages) == 1:
            # The first request of a new loop run.
            self.run_index += 1
            self.calls["run"] += 1
        plan = self.runs[self.run_index]
        if plan == _RAISE:
            raise RuntimeError("the gateway dropped the run")
        if plan == _BUDGET:
            returns = sum(
                1
                for message in messages
                for part in getattr(message, "parts", [])
                if isinstance(part, ToolReturnPart)
            )
            return ModelResponse(
                parts=[ToolCallPart("t_enrich_ip", {"ip": f"198.51.100.{returns + 1}"})]
            )
        return ModelResponse(parts=[ToolCallPart(output, _report_args(plan, 0.8))])


async def _drive_real_loop(settings: Settings, arm: _ArmC) -> list[StepEvent]:
    settings.investigator_strategy = "ensemble"
    settings.investigator_emits_report = True
    settings.verdict_consistency_samples = 3
    settings.agent_tool_calls_limit = 8
    ctx = _make_ctx(settings)
    ctx.requested_run_class = "standard"

    async def _stub_enriched(aid: str, **_kw: Any) -> Any:
        return _stub_enriched_alert_context(aid)

    with (
        patch(
            "soc_ai.tools.get_alert_context.get_enriched_alert_context",
            side_effect=_stub_enriched,
        ),
        patch("soc_ai.agent.orchestrator.build_synthesizer_model", return_value=arm.model()),
        patch("soc_ai.agent.decision_templates.match_decision_template", return_value=None),
        patch("soc_ai.oracle.client.adjudicate", new=AsyncMock(return_value=None)),
    ):
        return [ev async for ev in investigate("alert-001", ctx=ctx)]


def _executed_tool_calls(events: list[StepEvent]) -> int:
    return sum(1 for p in _of(events, "tool_result") if p.get("tool_name") != "final_result")


async def test_two_runs_cut_at_the_budget_still_reach_a_majority(
    settings_kratos: Settings,
) -> None:
    """The primary loop and the second sample stop at 8 calls. Both vote."""
    arm = _ArmC(
        runs=[_BUDGET, "true_positive", _BUDGET],
        partials=["true_positive", "false_positive"],
    )
    events = await _drive_real_loop(settings_kratos, arm)

    assert arm.calls["run"] == 3
    assert arm.calls["partial"] == 2
    # The primary loop stopped at its budget, as the trail shows.
    assert [e["phase"] for e in _of(events, "error")] == ["investigation_loop_budget"]
    assert _executed_tool_calls(events) == 8
    vote = _of(events, "self_consistency_vote")[0]
    assert vote["tally"] == {"true_positive": 2, "false_positive": 1}
    assert vote["chosen_verdict"] == "true_positive"
    assert (vote["requested"], vote["voted"], vote["partial"], vote["dropped"]) == (3, 3, 2, 0)
    # A partial vote keeps the cut-short clamp and the budget note.
    assert vote["note"] == "self-consistency 2/3 agreed on true_positive"
    # Every run and every partial synthesis is on the usage record.
    samples = [u for u in _of(events, "usage") if "self_consistency_sample" in u]
    assert len(samples) == 3  # sample 1, sample 2 to its budget, its partial synthesis
    assert all(u["input_tokens"] > 0 for u in samples)


async def test_two_samples_cut_at_the_budget_vote_with_their_partial_verdicts(
    settings_kratos: Settings,
) -> None:
    arm = _ArmC(
        runs=["false_positive", _BUDGET, _BUDGET],
        partials=["false_positive", "true_positive"],
    )
    events = await _drive_real_loop(settings_kratos, arm)

    assert not _of(events, "error")
    vote = _of(events, "self_consistency_vote")[0]
    assert vote["chosen_verdict"] == "false_positive"
    assert (vote["voted"], vote["partial"], vote["dropped"]) == (3, 2, 0)
    sample_tool_calls = sum(
        u["tool_calls"] for u in _of(events, "usage") if "self_consistency_sample" in u
    )
    # Each sample ran to its own budget of 8 calls.
    assert sample_tool_calls == 16


async def test_only_a_run_that_raises_is_dropped(settings_kratos: Settings) -> None:
    arm = _ArmC(runs=["true_positive", _RAISE, _BUDGET], partials=["true_positive"])
    events = await _drive_real_loop(settings_kratos, arm)

    vote = _of(events, "self_consistency_vote")[0]
    assert vote["tally"] == {"true_positive": 2}
    assert (vote["requested"], vote["voted"], vote["partial"], vote["dropped"]) == (3, 2, 1, 1)


async def test_a_budget_cut_with_the_vote_off_runs_no_sample(settings_kratos: Settings) -> None:
    """Negative control: one sample keeps the single path. The cut lands, and nothing votes."""
    arm = _ArmC(runs=[_BUDGET], partials=["true_positive"])
    settings_kratos.investigator_emits_report = True
    settings_kratos.agent_tool_calls_limit = 8
    ctx = _make_ctx(settings_kratos)
    ctx.requested_run_class = "standard"

    async def _stub_enriched(aid: str, **_kw: Any) -> Any:
        return _stub_enriched_alert_context(aid)

    with (
        patch(
            "soc_ai.tools.get_alert_context.get_enriched_alert_context",
            side_effect=_stub_enriched,
        ),
        patch("soc_ai.agent.orchestrator.build_synthesizer_model", return_value=arm.model()),
        patch("soc_ai.agent.decision_templates.match_decision_template", return_value=None),
        patch("soc_ai.oracle.client.adjudicate", new=AsyncMock(return_value=None)),
    ):
        events = [ev async for ev in investigate("alert-001", ctx=ctx)]

    assert arm.calls == {"run": 1, "partial": 1}
    assert not _of(events, "self_consistency_vote")
    assert "stopped at the tool-call budget" in _report(events)["summary"]
