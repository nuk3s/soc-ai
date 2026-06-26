"""Tests for soc_ai.agent.reasoning — <think> trace extraction."""

from __future__ import annotations

from soc_ai.agent.reasoning import ReasoningMode, extract_reasoning_trace, reasoning_extra_body


def test_extract_well_formed_think_block() -> None:
    trace, content = extract_reasoning_trace("<think>let me think</think>The answer is 42.")
    assert trace == "let me think"
    assert content == "The answer is 42."


def test_extract_no_think_block() -> None:
    assert extract_reasoning_trace("just a plain answer") == (None, "just a plain answer")


def test_extract_empty() -> None:
    assert extract_reasoning_trace("") == (None, "")


def test_extract_strips_all_blocks_returns_first_as_trace() -> None:
    trace, content = extract_reasoning_trace("<think>a</think>X<think>b</think>Y")
    assert trace == "a"
    assert content == "XY"


def test_unterminated_think_does_not_leak_into_content() -> None:
    """Truncated mid-trace (token cap): opening <think>, no closer. The whole
    trace must be captured as the trace, NOT leaked into the analyst-facing
    final content."""
    trace, content = extract_reasoning_trace("<think>reasoning got cut off here")
    assert trace == "reasoning got cut off here"
    assert content == ""


def test_unterminated_think_with_leading_whitespace() -> None:
    trace, content = extract_reasoning_trace("\n  <think>partial trace")
    assert trace == "partial trace"
    assert content == ""


def test_reasoning_extra_body_shape() -> None:
    body = reasoning_extra_body(ReasoningMode.FULL)
    assert body["reasoning"] == {"mode": "full"}
    assert body["chat_template_kwargs"] == {"thinking_mode": "full"}
