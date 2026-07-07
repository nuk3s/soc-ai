"""Scripted, deterministic model doubles for the golden-pipeline gate.

The orchestrator builds three kinds of model-driven agents:

* the **synth-first agent** (``build_synth_first_agent`` → round-1 synth and
  every Phase-D round-2 synth) — output_type ``TriageReport``,
* the **loop investigator** (``build_investigator``) — output_type
  ``InvestigationTranscript``, tool-equipped, driven via ``agent.iter()``,
* the **loop synthesizer** (``build_synthesizer``) — output_type
  ``TriageReport``, concludes over the loop transcript.

Rather than script real ``ModelResponse`` objects (fiddly, version-coupled),
this module follows the established ``tests/test_agent.py`` pattern: it patches
the agent BUILDERS to return fakes whose ``.run`` / ``.iter`` are mocked to
replay per-call scripted outputs. Every double is fully in-process — no
network, no LiteLLM, no real model.

The public entry point is :func:`patch_models_for_scenario`, a context manager
that installs the doubles for a whole :class:`~tests.golden.scenarios.ModelScript`.
"""

from __future__ import annotations

import contextlib
from collections.abc import Iterator, Sequence
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

from soc_ai.agent.triage import InvestigationTranscript, TriageReport

# A fixed usage namespace — the orchestrator's ``_usage_ev`` reads these five
# attributes off ``result.usage()``. Values are arbitrary but non-zero so the
# usage event is well-formed.
_FAKE_USAGE = SimpleNamespace(
    tool_calls=1, requests=2, input_tokens=10, output_tokens=5, total_tokens=15
)


def _run_result(output: Any) -> MagicMock:
    """A stand-in pydantic-ai ``AgentRunResult``: ``.output`` + ``.usage()``.

    ``.all_messages()`` returns an empty list — a zero-tool synth run has no
    message history the pipeline needs to walk (the reasoning projection is
    defensive and simply emits nothing).
    """
    result = MagicMock()
    result.output = output
    result.usage = MagicMock(return_value=_FAKE_USAGE)
    result.all_messages = MagicMock(return_value=[])
    return result


class _ToolCallPart(SimpleNamespace):
    """Mimics pydantic-ai's ``ToolCallPart`` (projected by ``_walk_message``)."""


class _ToolReturnPart(SimpleNamespace):
    """Mimics pydantic-ai's ``ToolReturnPart`` (counts as a successful call)."""


def _loop_message(tool_calls: Sequence[dict[str, Any]]) -> SimpleNamespace:
    """Build ONE investigator message carrying paired tool call + return parts.

    Each ``tool_calls`` entry is ``{name, args, result}``. The RETURN part is
    what ``count_successful_tool_calls`` counts, and only a loop with >=1
    successful call earns the evidence-gate exemption
    (``orchestrator._loop_evidence_marker``).
    """
    parts: list[Any] = []
    for i, tc in enumerate(tool_calls):
        call_id = f"tc{i}"
        parts.append(
            _ToolCallPart(
                tool_name=tc["name"],
                args=tc.get("args", {}),
                tool_call_id=call_id,
            )
        )
        parts.append(
            _ToolReturnPart(
                tool_name=tc["name"],
                content=tc.get("result", {}),
                tool_call_id=call_id,
                part_kind="tool-return",
            )
        )
    return SimpleNamespace(parts=parts)


# --- async-iterable investigator run (mirrors test_agent._install_fake_iter) ---


class _FakeIterNode:
    """A pydantic-ai-style node whose ``model_response`` the pipeline projects."""

    def __init__(self, message: Any) -> None:
        self.model_response = message


class _FakeAgentRun:
    """Async-iterable run: yields one node per message, then exposes ``result``."""

    def __init__(self, messages: list[Any], result: Any) -> None:
        self._nodes = [_FakeIterNode(m) for m in messages]
        self.result = result

    def __aiter__(self) -> Any:
        return self._agen()

    async def _agen(self) -> Any:
        for node in self._nodes:
            yield node


class _FakeIterCM:
    def __init__(self, run: _FakeAgentRun) -> None:
        self._run = run

    async def __aenter__(self) -> _FakeAgentRun:
        return self._run

    async def __aexit__(self, *exc: Any) -> bool:
        return False


def _build_loop_investigator(script: Any) -> MagicMock:
    """A fake loop investigator whose ``iter()`` streams the scripted tool
    call/return parts and then exposes a settled ``InvestigationTranscript``."""
    messages = [_loop_message(script.investigator_tool_calls)]
    transcript = InvestigationTranscript(
        evidence=list(script.investigator_evidence),
        tentative_summary=script.investigator_summary,
        open_questions=[],
    )
    inv_result = _run_result(transcript)
    inv_result.all_messages = MagicMock(return_value=messages)

    fake = MagicMock()
    fake.iter = MagicMock(return_value=_FakeIterCM(_FakeAgentRun(messages, inv_result)))
    return fake


def _build_synth_agent(reports: list[TriageReport]) -> MagicMock:
    """A fake synth-first agent whose ``.run`` replays ``reports`` per call.

    The synth-first agent is reused across round-1 AND every Phase-D round-2
    synth, so ``.run`` is scripted by call index. Exhausting the list re-serves
    the last report (defensive — a self-consistency re-vote would re-run it, but
    the golden set keeps ``verdict_consistency_samples`` at the default 1).
    """
    fake = MagicMock()
    results = [_run_result(r) for r in reports]

    call_state = {"i": 0}

    async def _run(*_a: Any, **_kw: Any) -> Any:
        i = min(call_state["i"], len(results) - 1)
        call_state["i"] += 1
        return results[i]

    fake.run = AsyncMock(side_effect=_run)
    return fake


@contextlib.contextmanager
def patch_models_for_scenario(script: Any) -> Iterator[None]:
    """Install deterministic model doubles for a scenario's :class:`ModelScript`.

    Patches (mirroring ``tests/test_agent.py``):

    * ``build_synthesizer_model`` — returns a harmless ``TestModel`` so any
      un-patched builder call still constructs a valid (offline) model. The
      synth-first + loop-synth agents below override the actual outputs.
    * ``build_synth_first_agent`` — the scripted synth-first agent (round-1 +
      Phase-D round-2 outputs).
    * ``build_synthesizer`` — the scripted loop synthesizer (its round-2 report)
      when the scenario enters the investigation loop.
    * ``build_investigator`` — the scripted loop investigator when the scenario
      enters the investigation loop.

    Only the builders the scenario actually reaches are exercised; the rest are
    still patched to safe doubles so no real model is ever constructed.
    """
    # Local import so the module imports even if pydantic_ai isn't importable at
    # collection time in an odd environment (it always is under `uv run`).
    from pydantic_ai.models.test import TestModel

    synth_first_agent = _build_synth_agent(script.synth_reports)

    # The loop synthesizer concludes the investigation loop with round-2's
    # report. When a scenario doesn't enter the loop this double is never
    # consulted; we still give it the last synth report as a safe output.
    loop_report = script.loop_synth_report or (
        script.synth_reports[-1] if script.synth_reports else None
    )
    loop_synth_agent = _build_synth_agent([loop_report] if loop_report is not None else [])

    loop_investigator = _build_loop_investigator(script)

    safe_model = TestModel(
        call_tools=[],
        custom_output_args=(script.synth_reports[0] if script.synth_reports else None),
    )

    with (
        patch(
            "soc_ai.agent.orchestrator.build_synthesizer_model",
            return_value=safe_model,
        ),
        patch(
            "soc_ai.agent.orchestrator.build_synth_first_agent",
            return_value=synth_first_agent,
        ),
        patch(
            "soc_ai.agent.orchestrator.build_synthesizer",
            return_value=loop_synth_agent,
        ),
        patch(
            "soc_ai.agent.orchestrator.build_investigator",
            return_value=loop_investigator,
        ),
    ):
        yield
