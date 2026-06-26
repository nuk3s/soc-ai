"""Thin LiteLLM-backed client for the cloud oracle.

soc-ai's LiteLLM gateway exposes the oracle model as an alias and
forwards requests via an OAuth proxy to the cloud model. soc-ai never
sees the upstream OAuth token; the LiteLLM gateway holds the
credentials.

We use LiteLLM's OpenAI-compatible surface (`/v1/chat/completions`)
since that's the same endpoint soc-ai already uses for its Nemotron
calls — one auth path, one trust boundary, one verify_ssl knob.

The `cache_control: ephemeral` hint is preserved inside system-
message content blocks; LiteLLM passes it through unchanged when the
upstream model supports prompt caching. The system prompt +
architecture context are stable across runs so caching them saves
~80% of input tokens on repeat runs.

We talk to LiteLLM via raw httpx rather than the openai SDK so the
unusual `cache_control` field on text content blocks is guaranteed to
survive serialization (the SDK's typed transformers can silently drop
unknown keys depending on version).

Usage::

    response = call_oracle(
        base_url="https://your-litellm-gateway",
        api_key="<litellm key>",
        verify_ssl=True,
        model="claude-opus-4-7",
        max_tokens=8192,
        system_prompt=SYSTEM_PROMPT,
        arch_context=architecture_block(),
        user_message=build_user_message(...),
    )
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any


@dataclass
class OracleResponse:
    """Captured response from a LiteLLM/oracle call."""

    text: str
    model: str
    usage: dict[str, int]
    elapsed_ms: int


class OracleError(RuntimeError):
    """Wraps any failure during the LiteLLM/oracle call (HTTP, transport, etc).

    The harness translates this into a clean CLI exit code; the bundle's
    ``meta.json`` records the failure for debugging.
    """


def call_oracle(
    *,
    base_url: str,
    api_key: str,
    verify_ssl: bool,
    model: str,
    max_tokens: int,
    system_prompt: str,
    user_message: str,
    arch_context: str | None = None,
    timeout_s: float = 300.0,
) -> OracleResponse:
    """POST a single-shot critique request to LiteLLM (which proxies to the oracle).

    System prompt (and optionally an architecture-context block) get
    the ``cache_control: ephemeral`` hint so repeat runs share most of
    the input cost. LiteLLM passes the hint through to the upstream
    model. Pass ``arch_context=None`` for the meta-analysis path, which
    doesn't need the agent's verbatim prompts in context.
    """
    import httpx  # noqa: PLC0415 - lazy import keeps soc-ai's hot path light

    url = str(base_url).rstrip("/") + "/v1/chat/completions"
    # Default ephemeral TTL is 5 minutes — too short for
    # eval batches where alerts can take 5+ min each, evicting the cached
    # system prompt + arch_context between consecutive runs. The
    # `extended-cache-ttl-2025-04-11` beta header allows
    # `ttl: "1h"` on cache_control blocks. A low cache-hit rate was
    # driven primarily by 30-min timeouts evicting the cache; with this
    # bump the cached prefix survives the entire batch.
    cache_hint: dict[str, Any] = {"type": "ephemeral", "ttl": "1h"}
    system_blocks: list[dict[str, Any]] = [
        {
            "type": "text",
            "text": system_prompt,
            "cache_control": cache_hint,
        }
    ]
    if arch_context:
        system_blocks.append(
            {
                "type": "text",
                "text": arch_context,
                "cache_control": cache_hint,
            }
        )
    payload: dict[str, Any] = {
        "model": model,
        "max_tokens": max_tokens,
        "messages": [
            {"role": "system", "content": system_blocks},
            {"role": "user", "content": user_message},
        ],
    }
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
        # Opt into the 1h cache TTL beta. LiteLLM forwards the beta
        # header unchanged when the upstream supports prompt caching.
        # The gateway returns HTTP 200 with cache_read_input_tokens
        # populated as expected.
        "anthropic-beta": "extended-cache-ttl-2025-04-11",
    }

    started = time.monotonic()
    try:
        with httpx.Client(verify=verify_ssl, timeout=timeout_s) as client:
            r = client.post(url, headers=headers, json=payload)
            r.raise_for_status()
            data = r.json()
    except httpx.HTTPStatusError as e:
        body = e.response.text[:500] if e.response is not None else ""
        raise OracleError(f"LiteLLM returned {e.response.status_code}: {body}") from e
    except httpx.HTTPError as e:
        raise OracleError(f"transport error talking to LiteLLM: {e}") from e
    except ValueError as e:
        raise OracleError(f"LiteLLM returned non-JSON body: {e}") from e
    elapsed_ms = int((time.monotonic() - started) * 1000)

    choices = data.get("choices") or []
    text = ""
    if choices:
        msg = choices[0].get("message") or {}
        content = msg.get("content")
        if isinstance(content, str):
            text = content
        elif isinstance(content, list):
            text = "".join(
                part.get("text", "")
                for part in content
                if isinstance(part, dict) and part.get("type") == "text"
            )

    raw_usage = data.get("usage") or {}
    details = raw_usage.get("prompt_tokens_details") or {}
    # Some batches showed `output_tokens=1` for every
    # row even though `response.md` was 5K-10K characters — LiteLLM's
    # OpenAI-shape conversion silently underreported `completion_tokens`
    # for oracle responses. Defend against that by:
    # 1. preferring the OpenAI-shape `completion_tokens`,
    # 2. falling back to the native `output_tokens` if it leaks
    #    through (some LiteLLM versions pass it through unchanged),
    # 3. estimating from the response text when both are obviously bogus
    #    (≤2 tokens for a >100-char response).
    reported_out = int(raw_usage.get("completion_tokens") or 0)
    anthropic_out = int(raw_usage.get("output_tokens") or 0)
    output_tokens = max(reported_out, anthropic_out)
    estimated_out = 0
    if output_tokens <= 2 and len(text) > 100:
        # Conservative ~4 chars/token estimate (English prose w/ markdown).
        estimated_out = len(text) // 4
        output_tokens = max(output_tokens, estimated_out)
    usage: dict[str, int] = {
        "input_tokens": int(raw_usage.get("prompt_tokens") or raw_usage.get("input_tokens") or 0),
        "output_tokens": output_tokens,
        "output_tokens_reported": reported_out,
        # When non-zero, the harness inferred output_tokens from text length
        # because the API-reported value was implausibly low (LiteLLM
        # accounting bug for oracle completions).
        "output_tokens_estimated": estimated_out,
        "cache_read_input_tokens": int(
            details.get("cached_tokens") or raw_usage.get("cache_read_input_tokens") or 0
        ),
        # LiteLLM may surface the cache-creation count under the
        # `cache_creation_input_tokens` key directly on usage; capture
        # whichever shape we see so meta.json reflects reality.
        "cache_creation_input_tokens": int(raw_usage.get("cache_creation_input_tokens") or 0),
    }

    return OracleResponse(
        text=text,
        model=str(data.get("model") or model),
        usage=usage,
        elapsed_ms=elapsed_ms,
    )
