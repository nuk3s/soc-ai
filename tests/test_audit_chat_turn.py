"""Chat turn engine: the SMB-only grounding failure through ground-or-strip.

A reply that anchors on the alert's own IP and adds an SMB/file-share story with
no SMB evidence anywhere in the corpus used to reach the engine as
``grounded=False`` with nothing in ``ungrounded``. The regrounding loop and the
terminal redaction both key off that list, so the fabricated claim shipped
verbatim — under a quiet line telling the analyst something had been removed.
The quiet line is gone too (2026-10-02): a claim leaves with its sentence, and
nothing says so.
"""

from __future__ import annotations

from soc_ai.agent.context import InvestigationContext
from soc_ai.agent.narrative_grounding import NOTHING_GROUNDED_REPLY
from soc_ai.webui.chat_turn import TurnInputs, run_chat_turn

from tests.test_chat_turn import _TEMPLATE, _Agent, _ctx, _Finish, _patched, _spec, _state

_SMB_ANSWER = "The host at 10.0.0.5 opened SMB shares against the file server."


async def test_smb_only_ungrounded_claim_is_stripped_with_its_sentence() -> None:
    state = _state()
    ctx = _ctx(state)
    finish = _Finish()

    async def _prepare() -> TurnInputs:
        return TurnInputs(
            ctx=ctx,
            seed_context="Grid: lab 10.0.0.5",
            question="q",
            system_prompt=_TEMPLATE,
            build_agent=lambda _m, c, _p: _Agent(c, [_SMB_ANSWER], tools=[]),
        )

    with _patched():
        await run_chat_turn(state, _spec(prepare=_prepare, finish=finish))

    content = finish.last["content"]
    grounding = finish.last["meta"]["narrative_grounding"]
    assert grounding["grounded"] is False
    assert grounding["stripped"] != []
    assert "smb" not in content.lower()
    assert "(unverified)" not in content
    # The one sentence carried the claim, so the reply says no statement had
    # support. An empty reply would read as an answer.
    assert content == NOTHING_GROUNDED_REPLY


async def test_smb_only_ungrounded_claim_triggers_the_regrounding_retry() -> None:
    """With a regrounding budget, the SMB-only failure must spend it: the agent
    gets a correction naming the claim, and its verified re-answer ships clean."""
    state = _state(chat_regrounding_attempts=1)
    ctx = _ctx(state)
    finish = _Finish()
    agents: list[_Agent] = []

    def _build(_m: object, c: InvestigationContext, _p: str) -> _Agent:
        agent = _Agent(c, [_SMB_ANSWER, "The host at 10.0.0.5 scanned 10.0.0.9."], tools=[])
        agents.append(agent)
        return agent

    async def _prepare() -> TurnInputs:
        return TurnInputs(
            ctx=ctx,
            seed_context="Grid: lab 10.0.0.5 -> 10.0.0.9",
            question="q",
            system_prompt=_TEMPLATE,
            build_agent=_build,
        )

    with _patched():
        await run_chat_turn(state, _spec(prepare=_prepare, finish=finish))

    assert len(agents[0].prompts) == 2
    assert "smb" in agents[0].prompts[1].lower()
    assert finish.last["meta"]["regrounding_attempts"] == 1
    assert finish.last["meta"]["narrative_grounding"] == {"grounded": True}
    assert "Some unverifiable specifics were removed" not in finish.last["content"]
