"""Close the grounding loop: make the agent fix ungrounded claims (2026-08-06).

The narrative-grounding validator has always DETECTED fabricated per-event
artifacts and only ever appended a caveat. During the 2026-08-05 incident that
was decisive: the chat asserted ``auth.success=true`` to justify overturning a
correct true_positive verdict, the validator flagged exactly that claim as
ungrounded, and the answer shipped anyway — caveat attached, verdict flipped.

The owner's question was the right one: why warn when you can tell the agent to
cite it or drop it? These tests pin that loop — the validator's finding is fed
back as a correction prompt, bounded, with today's caveat as the terminal
fallback when the agent will not comply.
"""

from __future__ import annotations

from soc_ai.agent.narrative_grounding import regrounding_instruction


def test_instruction_names_the_offending_claims() -> None:
    """The agent can only fix what it is told is broken."""
    text = regrounding_instruction(["auth.success", "DESKTOP-JSM4N2P"])
    assert "auth.success" in text
    assert "DESKTOP-JSM4N2P" in text


def test_instruction_offers_both_legitimate_resolutions() -> None:
    """Cite it from tool output, or drop it. Never 'soften it' — hedged
    fabrication is still fabrication."""
    text = regrounding_instruction(["auth.success"]).lower()
    assert "tool" in text  # verify via a tool call
    assert "remove" in text or "drop" in text  # or take the claim out


def test_instruction_forbids_inventing_support() -> None:
    """The failure mode this must not create: the agent 'grounding' a claim by
    asserting a tool result it never got."""
    text = regrounding_instruction(["auth.success"]).lower()
    assert "do not" in text or "never" in text


def test_instruction_is_stable_and_bounded() -> None:
    """Long ungrounded lists must not blow the turn's context."""
    text = regrounding_instruction([f"artifact-{i}" for i in range(50)])
    assert len(text) < 2000


def test_empty_list_yields_no_instruction() -> None:
    """No finding, no correction prompt."""
    assert regrounding_instruction([]) == ""


# ── Wiring: the loop must actually run, and must fail safe ──────────────────


def test_setting_exists_and_defaults_to_one_attempt() -> None:
    """Default ON at 1: the common case is a single over-reach the agent fixes
    immediately. 0 restores the historical warn-only behavior."""
    from pydantic import SecretStr
    from soc_ai.config import Settings

    s = Settings(
        so_host="https://so.example.com",
        so_username="analyst",
        so_password=SecretStr("password123"),
        es_hosts=["https://so.example.com:9200"],
        litellm_base_url="http://localhost:4000",
        api_auth_required=False,
    )
    assert s.chat_regrounding_attempts == 1


def test_chat_turn_reruns_on_ungrounded_and_keeps_caveat_fallback() -> None:
    """Pin the two halves of the contract in the turn engine's source: the loop
    re-runs the agent with the correction, and the caveat path survives as the
    terminal fallback when the agent will not comply."""
    import inspect

    from soc_ai.webui import chat_turn

    src = inspect.getsource(chat_turn)
    assert "regrounding_instruction" in src
    assert "chat_regrounding_attempts" in src
    # Re-runs the agent inside the loop, not just once.
    assert src.count("await agent.run(") >= 2
    # And the historical caveat is still applied when grounding ultimately fails.
    assert "scoped_unverified_caveat" in src
    assert "regrounding_attempts" in src
