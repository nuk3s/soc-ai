"""The agent-side surface of the Dashboard's general chat (design step C4).

Three things are under test, and each exists because a copy-paste would have
been the cheap way to get them wrong:

1. ``GENERAL_CHAT_SYSTEM_PROMPT`` is a SIBLING of ``CHAT_SYSTEM_PROMPT``, not a
   fork. The trust rules that stop a read-only agent rationalising (never invent
   per-event facts, external indicators only, answer shape, try the tool before
   saying you can't) must be the SAME TEXT in both — the hunt chat forked this
   prompt once and drifted. Only the scoping and the proposal tool differ.
2. ``build_general_context_block`` seeds the grid, because a general chat has no
   alert to anchor to — and ``seed_context`` is what
   :func:`check_narrative_grounding` grades against, so seeding the identifiers
   is what makes "your internal range is 192.168.10.0/24" a grounded answer
   rather than a caveated one.
3. ``propose_hunt`` mirrors ``propose_verdict``: registered only when the caller
   passes a sink, so the investigation chat's tool surface is untouched.
"""

from __future__ import annotations

import inspect
from ipaddress import ip_network
from typing import Any
from unittest.mock import AsyncMock

import pytest
from pydantic_ai import Agent
from pydantic_ai.models.test import TestModel
from soc_ai.agent.chat_agent import (
    CHAT_SYSTEM_PROMPT,
    GENERAL_CHAT_SYSTEM_PROMPT,
    build_chat_agent,
    build_general_context_block,
)
from soc_ai.agent.narrative_grounding import check_narrative_grounding
from soc_ai.agent.orchestrator import InvestigationContext
from soc_ai.agent.toolset import register_read_tools
from soc_ai.config import Settings
from soc_ai.oracle.identifiers import EffectiveIdentifiers


def _ctx(settings: Settings, **kwargs: Any) -> InvestigationContext:
    return InvestigationContext(settings=settings, auth=AsyncMock(), elastic=AsyncMock(), **kwargs)


def _names(agent: Any) -> set[str]:
    return set(agent._function_toolset.tools)


def _tool(agent: Any, name: str) -> Any:
    return agent._function_toolset.tools[name].function


def _identifiers() -> EffectiveIdentifiers:
    return EffectiveIdentifiers(
        suffixes=("lab.example",),
        hosts=("securityonion",),
        cidrs=[ip_network("192.168.10.0/24")],
    )


# ---------------------------------------------------------------------------
# 1. The prompt: a sibling, not a fork
# ---------------------------------------------------------------------------

# Blocks that MUST be byte-identical in both prompts. Each is a rule this
# project paid for in a live failure: the fabricated-DNS/SMB story (HARD RULE),
# an internal hostname sent to a public search engine (external indicators), the
# wall-of-prose answer (answer shape), and "I can't do that" from an agent that
# never called a tool (behaviour rule).
_SHARED_MARKERS = (
    "## HARD RULE — never invent per-event facts (this is non-negotiable)",
    "are HALLUCINATIONS, not answers, even if",
    "For web_search / crawl_page use \
EXTERNAL indicators ONLY — never put an internal IP/hostname in a web query.",
    "**A one-line bottom line in bold**",
    "An empty result is still an answer",
    '**Behaviour rule** — Do NOT tell the analyst "I can\'t do X" until you have actually \
tried the relevant tool.',
)


@pytest.mark.parametrize("marker", _SHARED_MARKERS)
def test_general_prompt_carries_the_investigation_chat_rules_verbatim(marker: str) -> None:
    assert marker in CHAT_SYSTEM_PROMPT, "marker drifted out of the investigation chat prompt"
    assert marker in GENERAL_CHAT_SYSTEM_PROMPT


def test_general_prompt_drops_the_investigation_scoping() -> None:
    """No alert to anchor to — so no single-alert scoping and no verdict tool."""
    assert "propose_verdict" not in GENERAL_CHAT_SYSTEM_PROMPT
    assert "ALREADY been completed" not in GENERAL_CHAT_SYSTEM_PROMPT
    assert "Stay scoped to this alert" not in GENERAL_CHAT_SYSTEM_PROMPT


def test_general_prompt_states_the_hunt_threshold_plainly() -> None:
    """A hunt is a multi-minute job; proposing one instead of answering is a
    worse answer. The threshold has to be in the prompt, not implied."""
    assert "propose_hunt" in GENERAL_CHAT_SYSTEM_PROMPT
    lowered = GENERAL_CHAT_SYSTEM_PROMPT.lower()
    assert "sweep" in lowered
    assert "many hosts" in lowered
    assert "answer" in lowered
    # It never launches one itself.
    assert "confirm" in lowered


def test_general_prompt_formats_with_a_seed_context() -> None:
    """A stray brace in a carried-over block would blow up .format() at runtime."""
    block = build_general_context_block(identifiers=_identifiers())
    rendered = GENERAL_CHAT_SYSTEM_PROMPT.format(context=block)
    assert block in rendered
    assert "{context}" not in rendered


# ---------------------------------------------------------------------------
# 2. The seed context: the grid is the anchor
# ---------------------------------------------------------------------------


def test_context_block_names_the_effective_identifiers() -> None:
    block = build_general_context_block(identifiers=_identifiers())
    assert "192.168.10.0/24" in block
    assert "lab.example" in block
    assert "securityonion" in block


def test_context_block_carries_the_dataset_inventory() -> None:
    inventory = "## Data available on this grid (auto-discovered)\n- `zeek.conn` — 1.2M · now"
    block = build_general_context_block(identifiers=_identifiers(), inventory_block=inventory)
    assert "zeek.conn" in block


def test_context_block_carries_recent_posture() -> None:
    block = build_general_context_block(
        identifiers=_identifiers(),
        verdict_counts={"true_positive": 2, "false_positive": 7, "needs_more_info": 1},
        top_rules=[("ET SCAN Potential SSH Scan", 412), ("ET INFO Observed DNS", 88)],
    )
    assert "false_positive" in block
    assert "7" in block
    assert "ET SCAN Potential SSH Scan" in block
    assert "412" in block
    assert "24h" in block or "24 h" in block


def test_context_block_survives_an_empty_grid() -> None:
    """SO down / a fresh install must still produce a usable seed, and must not
    leak a bare `None` into the prompt."""
    block = build_general_context_block()
    assert block.strip()
    assert "None" not in block


def test_context_block_is_bounded() -> None:
    """A busy grid must not blow the prompt budget on rule names."""
    block = build_general_context_block(
        identifiers=EffectiveIdentifiers(
            suffixes=tuple(f"s{i}.lan" for i in range(50)),
            hosts=tuple(f"host{i}" for i in range(50)),
            cidrs=[ip_network(f"10.{i}.0.0/16") for i in range(50)],
        ),
        top_rules=[(f"RULE {i} " + "x" * 400, 1000 - i) for i in range(50)],
    )
    assert len(block) < 4000, len(block)
    # The busiest rule survives the cap; the 50th does not.
    assert "RULE 0" in block
    assert "RULE 49" not in block


def test_seeded_identifiers_ground_an_answer_about_the_internal_range() -> None:
    """The second-order win: a correct answer about the network reads as GROUNDED.

    ``check_narrative_grounding`` grades the answer's artifacts against
    ``seed_context``. Without the identifiers in the seed, a general chat that
    correctly says "your internal range is 192.168.10.0/24" gets an ⚠ Unverified
    caveat stapled to a true statement.
    """
    block = build_general_context_block(identifiers=_identifiers())
    good = check_narrative_grounding(
        "**Your internal range is 192.168.10.0/24** and internal names end in lab.example.",
        seed_context=block,
        tool_evidence=[],
    )
    assert good.grounded, good.reason
    # Control: an address the grid never mentioned is still caught.
    bad = check_narrative_grounding(
        "**The domain controller is 192.0.2.77.**", seed_context=block, tool_evidence=[]
    )
    assert not bad.grounded
    assert "192.0.2.77" in bad.ungrounded


# ---------------------------------------------------------------------------
# 3. propose_hunt — the propose_verdict pattern, one tool over
# ---------------------------------------------------------------------------


def test_propose_hunt_is_absent_without_a_sink(settings_kratos: Settings) -> None:
    """The investigation chat's tool surface must not change (tests/
    test_tool_surface.py pins it by equality)."""
    agent = build_chat_agent(
        TestModel(call_tools=[]), _ctx(settings_kratos), system_prompt="chat", proposal_sink=[]
    )
    names = _names(agent)
    assert "propose_verdict" in names
    assert "propose_hunt" not in names


def test_propose_hunt_registers_on_a_hunt_sink(settings_kratos: Settings) -> None:
    agent = build_chat_agent(
        TestModel(call_tools=[]), _ctx(settings_kratos), system_prompt="general", hunt_sink=[]
    )
    names = _names(agent)
    assert "propose_hunt" in names
    # The general chat proposes hunts, never verdicts.
    assert "propose_verdict" not in names


@pytest.mark.asyncio
async def test_propose_hunt_records_the_proposal(settings_kratos: Settings) -> None:
    sink: list[dict[str, Any]] = []
    agent = build_chat_agent(
        TestModel(call_tools=[]), _ctx(settings_kratos), system_prompt="general", hunt_sink=sink
    )
    out = await _tool(agent, "propose_hunt")(
        objective="Sweep every internal host for outbound SSH to public IPs over 7 days",
        why="Answering this needs a per-host sweep across a week, not a single query.",
    )
    assert sink == [
        {
            "objective": "Sweep every internal host for outbound SSH to public IPs over 7 days",
            "why": "Answering this needs a per-host sweep across a week, not a single query.",
        }
    ]
    assert isinstance(out, str)
    assert out


# ---------------------------------------------------------------------------
# 4. default_window — a network question is not a 60-minute question
# ---------------------------------------------------------------------------

_WINDOWED_TOOLS = ("t_query_events_oql", "t_query_zeek_logs")


def _register(role: str, settings: Settings, **kwargs: Any) -> Agent[None, str]:
    agent: Agent[None, str] = Agent(TestModel(call_tools=[]), output_type=str, system_prompt="x")
    register_read_tools(agent, _ctx(settings), role=role, **kwargs)  # type: ignore[arg-type]
    return agent


def _window_default(agent: Any, tool: str) -> Any:
    fn = _tool(agent, tool)
    return inspect.signature(fn).parameters["time_range_minutes"].default


@pytest.mark.parametrize("tool", _WINDOWED_TOOLS)
def test_default_window_override_widens_the_chat_role(settings_kratos: Settings, tool: str) -> None:
    assert _window_default(_register("chat", settings_kratos), tool) == 60
    assert _window_default(_register("chat", settings_kratos, default_window=1440), tool) == 1440


@pytest.mark.parametrize("tool", _WINDOWED_TOOLS)
def test_role_windows_are_unchanged_without_an_override(
    settings_kratos: Settings, tool: str
) -> None:
    assert _window_default(_register("hunt", settings_kratos), tool) == 1440
    assert _window_default(_register("investigator", settings_kratos), tool) == 60


def test_default_window_override_does_not_change_the_tool_surface(
    settings_kratos: Settings,
) -> None:
    """No new role, no new/absent tool — only the window default moves."""
    assert _names(_register("chat", settings_kratos, default_window=1440)) == _names(
        _register("chat", settings_kratos)
    )


@pytest.mark.parametrize("tool", _WINDOWED_TOOLS)
def test_overridden_window_docs_drop_the_alert_anchor(settings_kratos: Settings, tool: str) -> None:
    """The LLM reads the docstring as the tool description. A general chat has no
    alert, so "the window is centered on the alert's @timestamp" is a false
    statement about its own behaviour (with no anchor the window is now-relative)
    AND contradicts the 1440 default sitting next to it."""
    doc = _tool(_register("chat", settings_kratos, default_window=1440), tool).__doc__ or ""
    assert "centered on the alert" not in doc
    assert "1440" in doc
    # Un-overridden roles keep the alert-anchored wording verbatim.
    anchored = _tool(_register("chat", settings_kratos), tool).__doc__ or ""
    assert "centered on the alert" in anchored


def test_build_chat_agent_forwards_the_window(settings_kratos: Settings) -> None:
    """The general chat reaches the toolset through build_chat_agent — an
    unreachable knob is not a knob."""
    agent = build_chat_agent(
        TestModel(call_tools=[]),
        _ctx(settings_kratos),
        system_prompt="general",
        hunt_sink=[],
        default_window=1440,
    )
    assert _window_default(agent, "t_query_events_oql") == 1440
