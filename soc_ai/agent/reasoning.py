"""Nemotron-style ``<think>`` reasoning trace handling.

Nemotron 3 (and similar reasoning models routed via LiteLLM) can emit a
``<think>...</think>`` block before the final response. soc-ai treats this
trace as **audit material**, not conversation context: we capture it
verbatim into the audit log, then strip it from the message we feed back
into the next turn so it never bloats the prompt or causes repetition.

Three reasoning modes are configurable per step (passed to LiteLLM via
``extra_body`` / chat-template flags):

- ``full`` - for triage decisions (verdict, recommended actions). The trace
  is genuinely useful analyst reading.
- ``low_effort`` - for tool-argument generation (the next OQL query).
- ``off`` - for routing classification (which model/path to use).
"""

from __future__ import annotations

import re
from enum import StrEnum

_THINK_RE = re.compile(r"<think>(.*?)</think>", re.DOTALL | re.IGNORECASE)
# A leading, unterminated ``<think>`` (truncated mid-trace before the closer).
_OPEN_THINK_RE = re.compile(r"\s*<think>(.*)", re.DOTALL | re.IGNORECASE)


class ReasoningMode(StrEnum):
    """Per-step reasoning mode enum.

    Values match the strings used in LiteLLM ``extra_body`` payloads.
    """

    FULL = "full"
    LOW_EFFORT = "low_effort"
    OFF = "off"


def extract_reasoning_trace(content: str) -> tuple[str | None, str]:
    """Split a model response into ``(trace, final_content)``.

    If the response contains one or more ``<think>...</think>`` blocks, the
    first match is returned as the trace and **all** matches are stripped
    from the final content. The returned trace is ``None`` when no thinking
    block is present.

    Examples
    --------
    >>> extract_reasoning_trace("<think>let me think</think>The answer is 42.")
    ('let me think', 'The answer is 42.')

    >>> extract_reasoning_trace("just a plain answer")
    (None, 'just a plain answer')

    >>> extract_reasoning_trace("<think>cut off mid-trace")
    ('cut off mid-trace', '')
    """
    if not content:
        return None, content
    match = _THINK_RE.search(content)
    if match is None:
        # Truncated mid-trace: an opening <think> with no closing tag (the
        # model hit a token cap before finishing). Without this, the entire
        # reasoning trace would leak into final_content — exactly what this
        # module exists to prevent. Treat everything after the opener as the
        # trace and leave the final content empty.
        open_match = _OPEN_THINK_RE.match(content)
        if open_match is not None:
            return open_match.group(1).strip(), ""
        return None, content
    trace = match.group(1).strip()
    cleaned = _THINK_RE.sub("", content).strip()
    return trace, cleaned


def reasoning_extra_body(mode: ReasoningMode) -> dict[str, object]:
    """Build the LiteLLM ``extra_body`` snippet that selects ``mode``.

    Different inference engines exposed via LiteLLM use slightly different
    flags for reasoning control. This helper emits the most common
    spellings together so a tolerant gateway picks the right one.
    """
    return {
        "reasoning": {"mode": mode.value},
        "chat_template_kwargs": {"thinking_mode": mode.value},
    }
