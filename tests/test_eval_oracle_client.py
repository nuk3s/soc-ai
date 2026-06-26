"""Unit tests for the LiteLLM-backed oracle client.

The client is a thin wrapper that:
- POSTs an OpenAI-style chat-completions request to LiteLLM
- preserves the `cache_control: ephemeral` hint inside system
  message content blocks (so LiteLLM forwards it to the oracle unchanged)
- normalizes the LiteLLM response into a small ``OracleResponse``
  dataclass with usage stats the harness's ``meta.json`` writer cares
  about (input/output/cache_read/cache_creation tokens).

These tests use ``respx`` to intercept the httpx request and assert
the exact payload shape we send to LiteLLM, plus the parsing path
for several response shapes.
"""

from __future__ import annotations

import httpx
import pytest
import respx
from soc_ai.eval.oracle_client import OracleError, call_oracle


@pytest.fixture
def captured_payload() -> dict:
    return {}


def _route(mock: respx.MockRouter, response: dict, status: int = 200) -> respx.Route:
    return mock.post("/v1/chat/completions").mock(
        return_value=httpx.Response(status, json=response)
    )


def test_call_oracle_sends_cache_control_in_system_message() -> None:
    """LiteLLM's prompt-cache pass-through requires `cache_control:
    ephemeral` to land *inside* the system message content blocks
    (not as a top-level kwarg). If the wire payload doesn't carry
    that field, we silently lose ~80% of the cost savings on repeat
    runs."""
    canned_response = {
        "model": "claude-opus-4-7",
        "choices": [{"message": {"content": "ok", "role": "assistant"}}],
        "usage": {"prompt_tokens": 100, "completion_tokens": 50},
    }
    with respx.mock(base_url="http://litellm.test:4000") as mock:
        route = _route(mock, canned_response)
        call_oracle(
            base_url="http://litellm.test:4000",
            api_key="test-key",
            verify_ssl=False,
            model="claude-opus-4-7",
            max_tokens=4096,
            system_prompt="SYS_PROMPT",
            arch_context="ARCH_CTX",
            user_message="USER_MSG",
        )

    body = route.calls[0].request.read().decode("utf-8")
    assert "cache_control" in body
    assert "ephemeral" in body
    assert "SYS_PROMPT" in body
    assert "ARCH_CTX" in body
    assert "USER_MSG" in body
    # cache_control includes a 1h TTL hint to survive 30+min batch gaps
    # (the gateway's default cache TTL is shorter).
    assert '"ttl": "1h"' in body or '"ttl":"1h"' in body
    # The beta header that opts into the extended TTL.
    headers = route.calls[0].request.headers
    assert headers.get("anthropic-beta") == "extended-cache-ttl-2025-04-11"


def test_call_oracle_sends_bearer_auth() -> None:
    """LiteLLM's auth is OpenAI-style `Authorization: Bearer ...`."""
    canned = {
        "model": "claude-opus-4-7",
        "choices": [{"message": {"content": "ok"}}],
        "usage": {"prompt_tokens": 1, "completion_tokens": 1},
    }
    with respx.mock(base_url="http://litellm.test:4000") as mock:
        route = _route(mock, canned)
        call_oracle(
            base_url="http://litellm.test:4000",
            api_key="my-secret",
            verify_ssl=False,
            model="claude-opus-4-7",
            max_tokens=10,
            system_prompt="s",
            arch_context="a",
            user_message="u",
        )

    headers = route.calls[0].request.headers
    assert headers["authorization"] == "Bearer my-secret"


def test_call_oracle_parses_string_content() -> None:
    """LiteLLM normalizes the upstream's responses to OpenAI shape;
    ``message.content`` arrives as a plain string."""
    canned = {
        "model": "claude-opus-4-7",
        "choices": [{"message": {"content": "hello world"}}],
        "usage": {"prompt_tokens": 10, "completion_tokens": 2},
    }
    with respx.mock(base_url="http://litellm.test:4000") as mock:
        _route(mock, canned)
        result = call_oracle(
            base_url="http://litellm.test:4000",
            api_key="k",
            verify_ssl=False,
            model="claude-opus-4-7",
            max_tokens=10,
            system_prompt="s",
            arch_context="a",
            user_message="u",
        )

    assert result.text == "hello world"
    assert result.model == "claude-opus-4-7"
    assert result.usage["input_tokens"] == 10
    assert result.usage["output_tokens"] == 2
    assert result.elapsed_ms >= 0


def test_call_oracle_parses_content_block_list() -> None:
    """Some LiteLLM versions surface ``content`` as a list of typed
    blocks (mirroring the upstream's native shape). Concatenate text
    blocks; ignore non-text."""
    canned = {
        "model": "claude-opus-4-7",
        "choices": [
            {
                "message": {
                    "content": [
                        {"type": "text", "text": "part one. "},
                        {"type": "text", "text": "part two."},
                    ]
                }
            }
        ],
        "usage": {"prompt_tokens": 5, "completion_tokens": 5},
    }
    with respx.mock(base_url="http://litellm.test:4000") as mock:
        _route(mock, canned)
        result = call_oracle(
            base_url="http://litellm.test:4000",
            api_key="k",
            verify_ssl=False,
            model="claude-opus-4-7",
            max_tokens=10,
            system_prompt="s",
            arch_context="a",
            user_message="u",
        )

    assert result.text == "part one. part two."


def test_call_oracle_extracts_cache_read_tokens() -> None:
    """LiteLLM exposes the upstream's cache stats under
    ``usage.prompt_tokens_details.cached_tokens`` so meta.json can
    show what fraction of the input came from the prompt cache."""
    canned = {
        "model": "claude-opus-4-7",
        "choices": [{"message": {"content": "ok"}}],
        "usage": {
            "prompt_tokens": 12000,
            "completion_tokens": 200,
            "prompt_tokens_details": {"cached_tokens": 9800},
        },
    }
    with respx.mock(base_url="http://litellm.test:4000") as mock:
        _route(mock, canned)
        result = call_oracle(
            base_url="http://litellm.test:4000",
            api_key="k",
            verify_ssl=False,
            model="claude-opus-4-7",
            max_tokens=10,
            system_prompt="s",
            arch_context="a",
            user_message="u",
        )

    assert result.usage["cache_read_input_tokens"] == 9800
    assert result.usage["input_tokens"] == 12000


def test_call_oracle_falls_back_to_anthropic_native_output_tokens() -> None:
    """F9 (issue #27): when LiteLLM passes through the upstream's native
    `output_tokens` instead of (or alongside) the OpenAI-shape
    `completion_tokens`, prefer the larger one."""
    canned = {
        "model": "claude-opus-4-7",
        "choices": [{"message": {"content": "ok"}}],
        "usage": {
            "prompt_tokens": 100,
            "completion_tokens": 0,  # OpenAI shape says 0...
            "output_tokens": 250,  # ...but Anthropic-native says 250
        },
    }
    with respx.mock(base_url="http://litellm.test:4000") as mock:
        _route(mock, canned)
        result = call_oracle(
            base_url="http://litellm.test:4000",
            api_key="k",
            verify_ssl=False,
            model="claude-opus-4-7",
            max_tokens=10,
            system_prompt="s",
            user_message="u",
        )

    assert result.usage["output_tokens"] == 250
    assert result.usage["output_tokens_reported"] == 0


def test_call_oracle_estimates_output_tokens_from_text_when_underreported() -> None:
    """F9 (issue #27): when both API-reported counts are implausibly low
    (≤2 tokens) for a non-trivial response (>100 chars), estimate from
    text length using ~4 chars/token. Phase 3 v5 batches showed every
    row's output_tokens=1 even with 5K-10K char response.md — without
    this fallback the metric was useless."""
    big_text = (
        "## 1. Verdict\n\nPartially. The agent's verdict is defensible "
        "but the rationale skips the rule-class signal. " * 30
    )
    canned = {
        "model": "claude-opus-4-7",
        "choices": [{"message": {"content": big_text}}],
        "usage": {"prompt_tokens": 50000, "completion_tokens": 1},
    }
    with respx.mock(base_url="http://litellm.test:4000") as mock:
        _route(mock, canned)
        result = call_oracle(
            base_url="http://litellm.test:4000",
            api_key="k",
            verify_ssl=False,
            model="claude-opus-4-7",
            max_tokens=8192,
            system_prompt="s",
            user_message="u",
        )

    assert result.usage["output_tokens"] >= 100  # estimated, not the bogus 1
    assert result.usage["output_tokens"] == len(big_text) // 4
    assert result.usage["output_tokens_reported"] == 1
    assert result.usage["output_tokens_estimated"] > 0


def test_call_oracle_keeps_real_output_tokens_unchanged() -> None:
    """F9 (issue #27): when API-reported output_tokens is plausible
    (>2 for any response), do NOT estimate. The fallback only kicks in
    on the bogus-low case."""
    canned = {
        "model": "claude-opus-4-7",
        "choices": [{"message": {"content": "ok"}}],
        "usage": {"prompt_tokens": 100, "completion_tokens": 47},
    }
    with respx.mock(base_url="http://litellm.test:4000") as mock:
        _route(mock, canned)
        result = call_oracle(
            base_url="http://litellm.test:4000",
            api_key="k",
            verify_ssl=False,
            model="claude-opus-4-7",
            max_tokens=10,
            system_prompt="s",
            user_message="u",
        )

    assert result.usage["output_tokens"] == 47
    assert result.usage["output_tokens_estimated"] == 0


def test_call_oracle_wraps_5xx_in_oracle_error() -> None:
    """A LiteLLM-side failure must become OracleError so the harness
    can map it to a clean exit code."""
    with respx.mock(base_url="http://litellm.test:4000") as mock:
        _route(mock, {"error": "upstream offline"}, status=503)
        with pytest.raises(OracleError, match="LiteLLM returned 503"):
            call_oracle(
                base_url="http://litellm.test:4000",
                api_key="k",
                verify_ssl=False,
                model="claude-opus-4-7",
                max_tokens=10,
                system_prompt="s",
                arch_context="a",
                user_message="u",
            )


def test_call_oracle_wraps_transport_errors() -> None:
    """A connection refused / DNS failure is wrapped, not raised raw."""
    with respx.mock(base_url="http://litellm.test:4000") as mock:
        mock.post("/v1/chat/completions").mock(side_effect=httpx.ConnectError("nope"))
        with pytest.raises(OracleError, match="transport error"):
            call_oracle(
                base_url="http://litellm.test:4000",
                api_key="k",
                verify_ssl=False,
                model="claude-opus-4-7",
                max_tokens=10,
                system_prompt="s",
                arch_context="a",
                user_message="u",
            )
