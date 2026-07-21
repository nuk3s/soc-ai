"""Shared replay helpers for budget-cut agent runs (hunt + investigation loop).

pydantic-ai raises ``UsageLimitExceeded`` AFTER the ``ModelResponse`` carrying
the next tool-call batch has landed in the history but BEFORE the calls
execute — so a budget-exhausted transcript ALWAYS ends with unprocessed tool
calls, and replaying it with a new user prompt is rejected with ``UserError:
Cannot provide a new user prompt when the message history contains unprocessed
tool calls`` (the 2026-07 prod hunt failure: every budget-capped hunt errored
and its evidence was discarded). These helpers repair such a transcript and
lift the model's own reasoning back into the follow-up synthesizer prompt so a
partial write-up can still land. Extracted from ``soc_ai.api.hunt_runner`` when
the triage investigation loop gained the same partial-synthesis path
(2026-07-18: budget-exhausted definitely-investigate triages discarded 25 tool
calls of evidence into a generic needs_more_info fallback).
"""

from __future__ import annotations

import logging
from typing import Any

from pydantic_ai.messages import ModelRequest, ModelResponse, ToolCallPart, ToolReturnPart

_LOGGER = logging.getLogger(__name__)

# Default closure content — the hunt path's original wording, kept verbatim so
# the shared extraction changed no hunt behavior. The triage loop passes an
# error-shaped dict instead so a synthetic closure can never be counted as
# gathered evidence by ``count_successful_tool_calls``.
HUNT_CLOSURE_CONTENT = "not executed — hunt budget exhausted"


def repair_dangling_tool_calls(
    gathered: list[Any], *, closure_content: Any = HUNT_CLOSURE_CONTENT
) -> list[Any]:
    """Close out unexecuted trailing tool calls so the transcript can be replayed.

    Appends a synthetic ``ModelRequest`` with one ``ToolReturnPart`` (content
    ``closure_content``) per dangling call in the trailing batch, preserving the
    model's final reasoning for the synthesizer. Returns a NEW list; ``gathered``
    is never mutated.

    Defensive by design — this path must never be able to crash the caller:
    if the trailing ``ModelResponse`` is any shape we can't repair (message-class
    drift after a pydantic-ai bump, surprise part payloads), fall back to
    TRIMMING it off — losing the final unexecuted step beats losing the whole
    report. The caller's error handling remains the LAST resort, not the first.
    """
    if not gathered:
        return gathered
    last = gathered[-1]
    if not isinstance(last, ModelResponse):
        return gathered  # tail already ends on a request — replayable as-is
    try:
        dangling = [p for p in last.parts if isinstance(p, ToolCallPart)]
        if not dangling:
            return gathered  # plain text/thinking tail — replayable as-is
        return [
            *gathered,
            ModelRequest(
                parts=[
                    ToolReturnPart(
                        tool_name=part.tool_name,
                        tool_call_id=part.tool_call_id,
                        content=closure_content,
                    )
                    for part in dangling
                ]
            ),
        ]
    except Exception:
        # Unexpected tail shape: trim the trailing ModelResponse rather than
        # replay a history pydantic-ai will reject.
        _LOGGER.warning(
            "could not close out dangling tool calls; trimming the trailing "
            "model response before partial synthesis",
            exc_info=True,
        )
        return gathered[:-1]


def replay_reasoning_context(gathered: list[Any]) -> str:
    """Surface the exploration model's own reasoning as explicit synthesizer input.

    The trust-erosion bug (two prod hunts, 2026-07): the exploration model had
    ALREADY debunked the false positive IN ITS REASONING ("Apple service
    discovery, not C2"), but that debunking lived in ``ThinkingPart``s the
    partial synthesizer never saw — pydantic-ai does NOT feed a prior turn's
    thinking back into a fresh agent's ``message_history`` (thinking is stripped
    from replayed context), so only the loud alert TITLES survived and the
    synthesizer reasserted the FP. This lifts the reasoning text back out of the
    gathered ``ModelResponse`` ``ThinkingPart``s and returns it as a plain-text
    block to prepend to the synthesizer's user message, so the model's own
    debunking is in front of it when it writes up a cut-short run.

    Returns ``""`` when there is no reasoning to replay (a non-reasoning model, or
    an empty trace) — the caller then simply omits the block. Defensive: any
    surprise part shape is skipped, never raised.
    """
    traces: list[str] = []
    for msg in gathered:
        for part in getattr(msg, "parts", None) or []:
            if type(part).__name__ != "ThinkingPart":
                continue
            content = str(getattr(part, "content", "") or "").strip()
            if content:
                traces.append(content)
    if not traces:
        return ""
    joined = "\n\n".join(traces)
    return (
        "## Your own reasoning from the exploration above (do NOT ignore it)\n"
        "While investigating you already reasoned about this evidence — "
        "including any false positives you debunked. That reasoning is NOT in "
        "the replayed message history, so it is reproduced here verbatim. "
        "Weight it: if you concluded an alert was a false positive (e.g. "
        "'solicited echo reply, not C2' / 'Apple service discovery, not a Linux "
        "backdoor'), do NOT reassert it as a threat now just because the alert "
        "title is loud.\n\n"
        f"{joined}\n\n---\n\n"
    )
